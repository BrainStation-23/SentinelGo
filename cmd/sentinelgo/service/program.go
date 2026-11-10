package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/enrollment"
	"sentinelgo/internal/lockfile"
	mdmpkg "sentinelgo/internal/osinfo/mdm"
	"sentinelgo/internal/osinfo/shared"
	systempkg "sentinelgo/internal/osinfo/system"
	"sentinelgo/internal/sanitize"
)

// lockName is the process lock shared by the service and -run (see
// lockfile.AgentLockName).
const lockName = lockfile.AgentLockName

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
	Cfg      *config.Config
	lockFile *lockfile.LockFile
	cancel   context.CancelFunc

	mu              sync.Mutex // guards mainIntegration, started late after first-boot enrollment
	mainIntegration *internal.MainIntegration
	enrollWG        sync.WaitGroup
}

// First-boot enrollment (#351). Vars so tests can stub them.
var (
	// enroll exchanges an enrollment token for agent credentials.
	enroll = enrollment.Enroll
	// enrollIdentity is what the backend checks the token against.
	enrollIdentity = func() enrollment.Identity {
		return identityFromMDM(systempkg.GetSerialNumber(), mdmpkg.Collect(""))
	}
	// enrollRetry is the wait before enrollment attempt n+1 (n >= 1).
	enrollRetry = func(n int) time.Duration {
		return min(30*time.Second<<min(n-1, 5), 15*time.Minute)
	}
	// tokenMayArriveLater is enrollment.TokenMayArriveLater.
	tokenMayArriveLater = enrollment.TokenMayArriveLater
	// exitProcess ends a service whose start after enrollment failed, so the
	// service manager restarts it instead of it running without an agent.
	exitProcess = os.Exit
)

// identityFromMDM builds the enrollment identity from the system serial and
// the same MDM collector the inventory's mdm.identity uses: the provisioning
// UDID on macOS, the OMA-DM DeviceID and SMBIOS UUID on Windows (#398). The
// collector leaves fields it doesn't have on an OS empty.
func identityFromMDM(serial string, info *shared.MDMInfo) enrollment.Identity {
	id := enrollment.Identity{Serial: serial}
	if info == nil {
		return id
	}
	id.ProvisioningUDID = info.Identity.ProvisioningUDID
	id.OMADMDeviceID = info.Identity.OMADMDeviceID
	id.SMBIOSUUID = info.Identity.SMBIOSUUID
	if info.Identity.Serial != "" {
		id.Serial = info.Identity.Serial
	}
	return id
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

	// A generic package has no config.json: enroll with a token first. With
	// no token yet where one can still arrive (the MDM can install the
	// package before the profile that carries it), or a failed exchange,
	// keep the service up and retry instead of exiting into a restart loop.
	// With no token where none will come, start as before: config
	// validation fails and the service exits with ExitConfigInvalid.
	if enrollment.Needed(p.Cfg) {
		err := p.tryEnroll(ctx)
		if err != nil && (tokenMayArriveLater || !errors.Is(err, enrollment.ErrNoToken)) {
			log.Printf("First-boot enrollment: %v; retrying in the background", err)
			emergencylog.Record("startup", "waiting for first-boot enrollment: %v", err)
			p.enrollWG.Add(1)
			go p.enrollThenStart(ctx)
			return nil
		}
	}
	return p.startIntegration(ctx)
}

// tryEnroll makes one first-boot enrollment attempt.
func (p *Program) tryEnroll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := enroll(ctx, p.Cfg, enrollIdentity()); err != nil {
		return err
	}
	log.Printf("First-boot enrollment: enrolled as agent %s", sanitize.ForLog(p.Cfg.AgentID))
	return nil
}

// enrollThenStart retries enrollment with backoff until it succeeds or the
// service stops, then starts the agent.
func (p *Program) enrollThenStart(ctx context.Context) {
	defer p.enrollWG.Done()
	for n := 1; ; n++ {
		t := time.NewTimer(enrollRetry(n))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := p.tryEnroll(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		if n == 1 || errors.Is(err, enrollment.ErrRejected) {
			log.Printf("First-boot enrollment: %v", err)
		}
	}
	if err := p.startIntegration(ctx); err != nil {
		emergencylog.Record("startup", "start after first-boot enrollment failed: %v", err)
		exitProcess(int(StartExitCode(err)))
	}
}

// startIntegration starts the agent proper.
func (p *Program) startIntegration(ctx context.Context) error {
	mi := internal.NewMainIntegration(p.Cfg)
	p.mu.Lock()
	p.mainIntegration = mi
	p.mu.Unlock()

	// Run startup synchronously so an initialization failure (config validation,
	// logging service init, scheduler start) propagates to the service manager,
	// which then marks the service failed and applies its restart policy —
	// instead of the previous behaviour where the service reported "running"
	// while the agent was actually dead. Start kicks off the long-running loops
	// in their own goroutines and returns promptly.
	if err := mi.Start(ctx); err != nil {
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
	p.enrollWG.Wait() // a pending first-boot enrollment ends with the context

	p.mu.Lock()
	mi := p.mainIntegration
	p.mu.Unlock()
	if mi != nil {
		if err := mi.Stop(); err != nil {
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
