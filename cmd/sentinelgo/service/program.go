package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/sanitize"
)

// lockName is the process lock shared by the service and -run. Both use the
// same name, and it has no version suffix, so no two agents (of any version,
// in any mode) run at once.
const lockName = "sentinelgo"

// newProcessLock returns the agent's process lock. Tests replace it to use a
// temporary path.
var newProcessLock = func() *lockfile.LockFile { return lockfile.NewLockFile(lockName) }

// Service-specific exit codes reported to the platform service manager when
// Start fails. On Windows `sc query SentinelGo` shows them as
// SERVICE_EXIT_CODE. Documented in docs/06-service-module.md.
const (
	ExitAlreadyRunning uint32 = 2 // another agent holds the process lock
	ExitLockError      uint32 = 3 // the lock file couldn't be opened or locked
	ExitConfigInvalid  uint32 = 4 // config failed to load or validate
	ExitStartupFailed  uint32 = 5 // any other startup failure (scheduler, audit logs, ...)
)

var (
	errConfigLoad  = errors.New("failed to load config")
	errProcessLock = errors.New("failed to acquire process lock")
)

// StartExitCode maps an error from Program.Start to its service exit code.
func StartExitCode(err error) uint32 {
	switch {
	case errors.Is(err, lockfile.ErrAlreadyRunning):
		return ExitAlreadyRunning
	case errors.Is(err, errProcessLock):
		return ExitLockError
	case errors.Is(err, errConfigLoad), errors.Is(err, internal.ErrConfigInvalid):
		return ExitConfigInvalid
	default:
		return ExitStartupFailed
	}
}

// acquireProcessLock takes the agent's process lock. The error wraps
// lockfile.ErrAlreadyRunning when another agent holds it, and errProcessLock
// when the lock file is unusable.
func acquireProcessLock() (*lockfile.LockFile, error) {
	lf := newProcessLock()
	err := lf.TryAcquire()
	switch {
	case err == nil:
		return lf, nil
	case errors.Is(err, lockfile.ErrAlreadyRunning):
		return nil, fmt.Errorf("%w (lock %s); stop it first with 'sentinelgo -stop'", err, lf.Path())
	case errors.Is(err, fs.ErrPermission):
		// The lock directory is restricted to SYSTEM/Administrators (root on
		// Linux and macOS), as is config.json next to it.
		return nil, fmt.Errorf("%w: %w; run as Administrator or root", errProcessLock, err)
	default:
		return nil, fmt.Errorf("%w: %w", errProcessLock, err)
	}
}

// Program implements the service start/stop lifecycle. It is constructed in
// main and passed to NewAgentService.
type Program struct {
	Cfg             *config.Config
	lockFile        *lockfile.LockFile
	mainIntegration *internal.MainIntegration
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
			return fmt.Errorf("%w: %w", errConfigLoad, err)
		}
	}

	version := agentVersion
	if version == "" {
		version = config.Version
	}
	if version == "" {
		version = "unknown"
	}

	// Point the emergency log at the runtime directory now, so a lock failure
	// is recorded too (MainIntegration.Start repeats this; it is idempotent).
	if err := emergencylog.Init(filepath.Dir(p.Cfg.Path)); err != nil {
		log.Printf("Warning: emergency log init failed (events echo to log only): %v", err)
	}

	lf, err := acquireProcessLock()
	if err != nil {
		emergencylog.Record("startup", "process lock not acquired (this is v%s): %v", sanitize.ForLog(version), err)
		return err
	}
	p.lockFile = lf

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.mainIntegration = internal.NewMainIntegration(p.Cfg)

	// Run startup synchronously so an initialization failure (config validation,
	// logging service init, scheduler start) propagates to the service manager,
	// which then marks the service failed and applies its restart policy —
	// instead of the previous behaviour where the service reported "running"
	// while the agent was actually dead. Start kicks off the long-running loops
	// in their own goroutines and returns promptly.
	if err := p.mainIntegration.Start(ctx); err != nil {
		log.Printf("FATAL: main integration failed to start: %v", err)
		// Release the lock we just acquired so a restart in this process (or a
		// -run) isn't refused while this failed start is still unwinding.
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
