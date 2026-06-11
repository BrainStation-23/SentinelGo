package service

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const (
	linuxUnitName = "sentinelgo"
	linuxUnitPath = "/etc/systemd/system/sentinelgo.service"
	linuxUnitFmt  = `[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
)

type linuxService struct {
	cfg ServiceConfig
	prg *Program
}

type linuxLogger struct{}

func (l *linuxLogger) Info(a ...interface{}) error {
	log.Println(a...)
	return nil
}

func (l *linuxLogger) Errorf(format string, a ...interface{}) error {
	log.Printf(format, a...)
	return nil
}

// NewAgentService returns the Linux AgentService and AgentLogger backed by
// subprocess calls to systemctl — mirroring the launchd.go pattern on macOS.
func NewAgentService(prg *Program, cfg ServiceConfig) (AgentService, AgentLogger, error) {
	return &linuxService{cfg: cfg, prg: prg}, &linuxLogger{}, nil
}

func (ls *linuxService) Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	parts := []string{exePath}
	parts = append(parts, ls.cfg.Arguments...)
	execStart := strings.Join(parts, " ")

	unit := fmt.Sprintf(linuxUnitFmt, ls.cfg.Description, execStart)
	if err := os.WriteFile(linuxUnitPath, []byte(unit), 0644); err != nil { //nolint:gosec // systemd unit files must be world-readable
		return fmt.Errorf("write unit file: %w", err)
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, out)
	}

	if out, err := exec.Command("systemctl", "enable", linuxUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %w: %s", err, out)
	}

	return nil
}

func (ls *linuxService) Start() error {
	if out, err := exec.Command("systemctl", "start", linuxUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl start: %w: %s", err, out)
	}
	return nil
}

func (ls *linuxService) Uninstall() error {
	_ = exec.Command("systemctl", "stop", linuxUnitName).Run()
	_ = exec.Command("systemctl", "disable", linuxUnitName).Run()

	if err := os.Remove(linuxUnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// Run starts the program goroutines directly (systemd manages the process
// lifetime) and blocks until SIGTERM or SIGINT.
func (ls *linuxService) Run() error {
	if err := ls.prg.Start(ls); err != nil {
		return fmt.Errorf("start program: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigChan)

	<-sigChan
	return ls.prg.Stop(ls)
}
