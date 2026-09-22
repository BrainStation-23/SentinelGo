package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"sentinelgo/internal/winsec"
)

// stopTimeout bounds how long Uninstall waits for the service to stop before
// deleting it.
const stopTimeout = 30 * time.Second

// recoveryActions restart the service after an unexpected exit.
//
// These are not merely a reliability nicety: the Windows update path replaces
// the binary in-process and then exits non-zero specifically so the SCM restarts
// it on the new image. Without recovery actions configured, "exit to apply the
// update" means "exit and stay down". install.bat configures the same policy via
// `sc failure`; a service installed through this code path previously had none
// at all.
var recoveryActions = []mgr.RecoveryAction{
	{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
}

// recoveryResetPeriod is the window after which the failure count resets, in
// seconds. A day is long enough that a genuine crash loop exhausts the actions,
// and short enough that an isolated failure months apart starts fresh.
const recoveryResetPeriod = 86400

type windowsService struct {
	name string
	cfg  ServiceConfig
	prg  *Program
}

type windowsLogger struct {
	elog *eventlog.Log
}

func (l *windowsLogger) Info(a ...interface{}) error {
	if l.elog != nil {
		return l.elog.Info(1, fmt.Sprint(a...))
	}
	log.Println(a...)
	return nil
}

func (l *windowsLogger) Errorf(format string, a ...interface{}) error {
	if l.elog != nil {
		return l.elog.Error(1, fmt.Sprintf(format, a...))
	}
	log.Printf(format, a...)
	return nil
}

// NewAgentService returns the Windows AgentService and AgentLogger backed by
// the Windows Service Control Manager via golang.org/x/sys/windows/svc (BSD-3-Clause).
func NewAgentService(prg *Program, cfg ServiceConfig) (AgentService, AgentLogger, error) {
	ws := &windowsService{name: cfg.Name, cfg: cfg, prg: prg}
	elog, err := eventlog.Open(cfg.Name)
	if err != nil {
		// Event source not yet registered (before first install) — fall back to log.
		return ws, &windowsLogger{elog: nil}, nil
	}
	return ws, &windowsLogger{elog: elog}, nil
}

func (ws *windowsService) Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Harden the binary and its directory BEFORE registering the service.
	//
	// Registering first would create a window in which the SCM is willing to
	// launch, as LocalSystem, a binary sitting in a directory that may still be
	// writable by any standard user. This also means an operator who runs
	// `sentinelgo.exe -install` by hand gets the same protection as one who runs
	// the installer, instead of silently getting none.
	//
	// Failure here is fatal: installing a LocalSystem service whose binary we
	// could not secure is the vulnerability, not a degraded state.
	installDir := filepath.Dir(exePath)
	if err := winsec.SecureSystemPath(installDir); err != nil {
		return fmt.Errorf("refusing to install: cannot secure install directory %s: %w",
			installDir, err)
	}
	if err := winsec.SecureSystemPath(exePath); err != nil {
		return fmt.Errorf("refusing to install: cannot secure binary %s: %w", exePath, err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	existing, err := m.OpenService(ws.name)
	if err == nil {
		_ = existing.Close()
		return fmt.Errorf("service %q already exists", ws.name)
	}

	s, err := m.CreateService(ws.name, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: ws.cfg.DisplayName,
		Description: ws.cfg.Description,
		// Run as LocalSystem explicitly rather than by omission, so the account
		// is stated in the code that chooses it.
		ServiceStartName: "LocalSystem",
		// Give the service its own SID (NT SERVICE\SentinelGo) in the process
		// token. It costs nothing for a LocalSystem service and makes it
		// possible to write ACLs scoped to this service rather than to all of
		// SYSTEM, which is the prerequisite for ever running as a lower-
		// privileged account.
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, ws.cfg.Arguments...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.SetRecoveryActions(recoveryActions, recoveryResetPeriod); err != nil {
		// Not fatal to the install, but the agent cannot self-update without it,
		// so it must be visible rather than silently swallowed.
		log.Printf("WARNING: failed to configure service recovery actions: %v. "+
			"The service will not restart automatically after a failure, and "+
			"automatic updates -- which exit and rely on the SCM to restart the "+
			"new binary -- will leave the service stopped.", err)
	}

	_ = eventlog.InstallAsEventCreate(ws.name, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

func (ws *windowsService) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(ws.name)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer func() { _ = s.Close() }()

	return s.Start(ws.cfg.Arguments...)
}

func (ws *windowsService) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(ws.name)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Stop before deleting. Delete on a running service only marks it for
	// deletion: the process keeps running and keeps its files open, so a
	// reinstall can recreate the install directory while the old binary is
	// still executing out of it.
	if err := stopAndWait(s); err != nil {
		log.Printf("WARNING: %v; deleting the service registration anyway", err)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	_ = eventlog.Remove(ws.name)
	return nil
}

// stopAndWait asks the service to stop and waits for it to do so.
func stopAndWait(s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		// Already stopped is not a problem; anything else is worth reporting.
		if current, qErr := s.Query(); qErr == nil && current.State == svc.Stopped {
			return nil
		}
		return fmt.Errorf("stop service: %w", err)
	}

	deadline := time.Now().Add(stopTimeout)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not stop within %s", stopTimeout)
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return fmt.Errorf("query service state: %w", err)
		}
	}
	return nil
}

// windowsHandler implements svc.Handler, driving the Program Start/Stop
// lifecycle in response to Windows SCM control requests.
type windowsHandler struct {
	ws *windowsService
}

func (h *windowsHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	if err := h.ws.prg.Start(h.ws); err != nil {
		log.Printf("Failed to start program: %v", err)
		return false, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			_ = h.ws.prg.Stop(h.ws)
			return false, 0
		}
	}
	return false, 0
}

func (ws *windowsService) Run() error {
	return svc.Run(ws.name, &windowsHandler{ws: ws})
}
