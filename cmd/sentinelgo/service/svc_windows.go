package service

import (
	"fmt"
	"log"
	"os"

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
		_ = existing.Close()
		return fmt.Errorf("service %q already exists", ws.name)
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
