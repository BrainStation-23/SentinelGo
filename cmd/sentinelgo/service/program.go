package service

import (
	"context"
	"fmt"
	"log"
	"os"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/migrate"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/selfdefense"
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

	// Relocate a legacy installation before anything else. Running first is what
	// serialises migration against the updater: no lock is held, no subsystem is
	// up, and no update can be in flight while files are moving.
	if result := migrate.Run(); result.RestartRequired {
		if err := logger.Info("SentinelGo relocated to the current layout; exiting for restart"); err != nil {
			fmt.Printf("Warning: failed to log migration message: %v\n", err)
		}
		// Exit non-zero so the service manager's failure actions restart the
		// service, which now points at the relocated binary.
		os.Exit(1)
	}

	// Verify we are running from a location a standard user cannot tamper with,
	// before acquiring the lock or starting any subsystem. Running this first
	// means the decision to disable updates and task execution is made before
	// MainIntegration can launch either of them.
	if result := selfdefense.Check(p.Cfg.Path); result.Fatal {
		return fmt.Errorf("integrity check failed: %s", result.Reason)
	}

	version := agentVersion
	if version == "" {
		version = config.Version
	}
	if version == "" {
		version = "unknown"
	}
	sanitizedVersion := sanitize.ForLog(version)

	// Use a single, version-INDEPENDENT lock name. A version-suffixed name let
	// two different versions run simultaneously (e.g. during/after an update),
	// producing double heartbeats and double audit uploads.
	lf := lockfile.NewLockFile("sentinelgo")

	locked, err := lf.CheckExistingLock()
	if err != nil {
		log.Printf("Warning: Failed to check existing lock: %v", err)
	} else if locked {
		log.Printf("Another instance of SentinelGo is already running (this is v%s)", sanitizedVersion)
		return fmt.Errorf("another instance is already running")
	}

	if err := lf.TryAcquire(); err != nil {
		log.Printf("Failed to acquire process lock: %v", err)
		return fmt.Errorf("failed to acquire process lock: %v", err)
	}
	p.lockFile = lf

	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.mainIntegration = internal.NewMainIntegration(p.Cfg)

	// Run startup synchronously so an initialization failure (config validation,
	// logging service init, scheduler start) propagates to the service manager,
	// which then marks the service failed and applies its restart policy —
	// instead of the previous behaviour where the service reported "running"
	// while the agent was actually dead. Start kicks off the long-running loops
	// in their own goroutines and returns promptly.
	if err := p.mainIntegration.Start(p.ctx); err != nil {
		log.Printf("FATAL: main integration failed to start: %v", err)
		// Release the lock we just acquired so a restart isn't blocked by a
		// stale lock held by this failed start.
		if relErr := p.lockFile.Release(); relErr != nil {
			log.Printf("Warning: failed to release lock after failed start: %v", relErr)
		}
		p.lockFile = nil
		p.cancel()
		return fmt.Errorf("main integration failed to start: %w", err)
	}

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
