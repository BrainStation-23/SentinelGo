package service

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

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

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	existing, err := m.OpenService(ws.name)
	if err == nil {
		if err := stopDeleteAndWait(existing, m, ws.name); err != nil {
			return err
		}
	}

	s, err := m.CreateService(ws.name, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: ws.cfg.DisplayName,
		Description: ws.cfg.Description,
	}, ws.cfg.Arguments...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	_ = s.Close()

	_ = eventlog.InstallAsEventCreate(ws.name, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

// stopDeleteAndWait makes `sentinelgo -install` a deterministic reinstall,
// matching install.bat. Deleting C:\SentinelGo does not unregister the SCM
// entry, and Windows can keep a deleted service marked for deletion until all
// handles close, so CreateService must not race the old registration.
func stopDeleteAndWait(existing *mgr.Service, manager *mgr.Mgr, name string) error {
	status, queryErr := existing.Query()
	if queryErr == nil && status.State != svc.Stopped {
		if _, err := existing.Control(svc.Stop); err != nil {
			_ = existing.Close()
			return fmt.Errorf("stop existing service %q: %w", name, err)
		}

		deadline := time.Now().Add(30 * time.Second)
		stopped := false
		for time.Now().Before(deadline) {
			currentStatus, err := existing.Query()
			if err != nil {
				_ = existing.Close()
				return fmt.Errorf("query existing service %q while stopping: %w", name, err)
			}
			if currentStatus.State == svc.Stopped {
				stopped = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !stopped {
			_ = existing.Close()
			return fmt.Errorf("existing service %q did not stop within 30 seconds", name)
		}
	}

	if err := existing.Delete(); err != nil {
		_ = existing.Close()
		return fmt.Errorf("delete existing service %q: %w", name, err)
	}
	if err := existing.Close(); err != nil {
		return fmt.Errorf("close existing service %q: %w", name, err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := manager.OpenService(name)
		if err != nil {
			return nil
		}
		_ = probe.Close()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("existing service %q is still registered after 30 seconds", name)
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

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	_ = eventlog.Remove(ws.name)
	return nil
}

// startFailureExitCode is reported to the SCM when the agent cannot start.
//
// It is returned as a SERVICE-SPECIFIC code (the true first return value of
// Execute), not a Win32 code. Returning a plain Win32 code of 1 made Windows
// render every startup failure as Event 7023 "Incorrect function" — technically
// what error 1 means, but useless for diagnosis, and the reason a simple
// missing supabase_url looked like a corrupt binary.
const startFailureExitCode = 1

// windowsHandler implements svc.Handler, driving the Program Start/Stop
// lifecycle in response to Windows SCM control requests.
type windowsHandler struct {
	ws *windowsService
}

func (h *windowsHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	if err := h.ws.prg.Start(h.ws); err != nil {
		// The SCM only ever surfaces a number, so the actual reason has to be
		// written somewhere an operator will look. The event log is that place:
		// stdout goes nowhere under the SCM, and the agent may have failed
		// before its own file logging was initialised.
		log.Printf("Failed to start program: %v", err)
		if logger != nil {
			_ = logger.Errorf("SentinelGo failed to start: %v", err)
		}
		return true, startFailureExitCode
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
