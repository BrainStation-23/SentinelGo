package service

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type darwinService struct {
	cfg ServiceConfig
	prg *Program
}

type darwinLogger struct{}

func (l *darwinLogger) Info(a ...interface{}) error {
	log.Println(a...)
	return nil
}

func (l *darwinLogger) Errorf(format string, a ...interface{}) error {
	log.Printf(format, a...)
	return nil
}

// NewAgentService returns the macOS AgentService and AgentLogger.
// HandleInstall and HandleUninstall bypass this interface entirely via launchd.go;
// only Run() is exercised in production (called when launchd starts the binary).
func NewAgentService(prg *Program, cfg ServiceConfig) (AgentService, AgentLogger, error) {
	return &darwinService{cfg: cfg, prg: prg}, &darwinLogger{}, nil
}

// Install is unreachable on macOS — HandleInstall returns early via launchd.go.
func (ds *darwinService) Install() error {
	return fmt.Errorf("unreachable: Install called on darwin")
}

// Start is unreachable on macOS — HandleInstall calls launchctl start directly.
func (ds *darwinService) Start() error {
	return fmt.Errorf("unreachable: Start called on darwin")
}

// Uninstall is unreachable on macOS — HandleUninstall returns early via launchd.go.
func (ds *darwinService) Uninstall() error {
	return fmt.Errorf("unreachable: Uninstall called on darwin")
}

// Run starts the program goroutines and blocks until launchd sends SIGTERM.
func (ds *darwinService) Run() error {
	if err := ds.prg.Start(ds); err != nil {
		return fmt.Errorf("start program: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigChan)

	<-sigChan
	return ds.prg.Stop(ds)
}
