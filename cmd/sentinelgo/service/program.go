package service

import (
	"context"
	"fmt"
	"log"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/sanitize"
)

// Program implements the service start/stop lifecycle. It is constructed in
// main and passed to NewAgentService.
type Program struct {
	Cfg             *config.Config
	lockFile        *lockfile.LockFile
	mainIntegration *internal.MainIntegration
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewProgram constructs a Program for the given config.
func NewProgram(cfg *config.Config) *Program {
	return &Program{Cfg: cfg}
}

// Start is called by the platform service manager to begin the agent.
func (p *Program) Start(_ AgentService) error {
	if err := logger.Info("Starting SentinelGo service"); err != nil {
		fmt.Printf("Warning: failed to log start message: %v\n", err)
	}

	if p.Cfg == nil {
		var err error
		p.Cfg, err = config.Load("")
		if err != nil {
			log.Printf("FATAL: Failed to load config: %v", err)
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	version := agentVersion
	if version == "" {
		version = config.Version
	}
	if version == "" {
		version = "unknown"
	}
	sanitizedVersion := sanitize.ForLog(version)
	lf := lockfile.NewLockFile(fmt.Sprintf("sentinelgo-%s", sanitizedVersion))

	locked, err := lf.CheckExistingLock()
	if err != nil {
		log.Printf("Warning: Failed to check existing lock: %v", err)
	} else if locked {
		log.Printf("Another instance of SentinelGo v%s is already running", sanitizedVersion)
		return fmt.Errorf("another instance is already running")
	}

	if err := lf.TryAcquire(); err != nil {
		log.Printf("Failed to acquire process lock: %v", err)
		return fmt.Errorf("failed to acquire process lock: %v", err)
	}
	p.lockFile = lf

	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.mainIntegration = internal.NewMainIntegration(p.Cfg)

	go func() {
		if err := p.mainIntegration.Start(p.ctx); err != nil {
			log.Printf("Main integration stopped with error: %v", err)
		}
	}()

	return nil
}

// Stop is called by the platform service manager to shut the agent down.
func (p *Program) Stop(_ AgentService) error {
	if err := logger.Info("Stopping SentinelGo service"); err != nil {
		fmt.Printf("Warning: failed to log stop message: %v\n", err)
	}

	if p.cancel != nil {
		p.cancel()
	}

	if p.mainIntegration != nil {
		if err := p.mainIntegration.Stop(); err != nil {
			log.Printf("Warning: Failed to stop main integration: %v", err)
		}
	}

	if p.lockFile != nil {
		if err := p.lockFile.Release(); err != nil {
			if err := logger.Errorf("Failed to release process lock: %v", err); err != nil {
				fmt.Printf("Warning: failed to log error: %v\n", err)
			}
		} else {
			if err := logger.Info("Released process lock"); err != nil {
				fmt.Printf("Warning: failed to log info: %v\n", err)
			}
		}
	}

	return nil
}
