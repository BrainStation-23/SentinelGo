package service

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
)

type nopLogger struct{}

func (nopLogger) Info(...interface{}) error           { return nil }
func (nopLogger) Errorf(string, ...interface{}) error { return nil }

// useTempLock points the process lock and the config directory at a temp dir
// and returns the lock path.
func useTempLock(t *testing.T) (lockPath string, cfg *config.Config) {
	t.Helper()
	dir := t.TempDir()
	lockPath = filepath.Join(dir, lockName+".lock")

	prevLock, prevLogger := newProcessLock, logger
	newProcessLock = func() *lockfile.LockFile { return lockfile.NewLockFileWithPath(lockPath) }
	logger = nopLogger{}
	t.Cleanup(func() { newProcessLock, logger = prevLock, prevLogger })

	// An empty config fails validation, so MainIntegration.Start returns
	// before it touches the network or the services DB.
	return lockPath, &config.Config{Path: filepath.Join(dir, "config.json")}
}

func TestProgramStart_AlreadyRunning(t *testing.T) {
	lockPath, cfg := useTempLock(t)
	holder := lockfile.NewLockFileWithPath(lockPath)
	if err := holder.TryAcquire(); err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	defer func() { _ = holder.Release() }()

	err := NewProgram(cfg).Start(nil)
	if !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Fatalf("Start() = %v, want ErrAlreadyRunning", err)
	}
	if code := StartExitCode(err); code != ExitAlreadyRunning {
		t.Errorf("StartExitCode() = %d, want %d", code, ExitAlreadyRunning)
	}
	// The original holder keeps the lock.
	if err := lockfile.NewLockFileWithPath(lockPath).TryAcquire(); !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Errorf("lock no longer held by the original holder: %v", err)
	}
}

func TestProgramStart_FailedStartReleasesLock(t *testing.T) {
	lockPath, cfg := useTempLock(t)

	p := NewProgram(cfg)
	err := p.Start(nil)
	if !errors.Is(err, internal.ErrConfigInvalid) {
		t.Fatalf("Start() = %v, want ErrConfigInvalid", err)
	}
	if code := StartExitCode(err); code != ExitConfigInvalid {
		t.Errorf("StartExitCode() = %d, want %d", code, ExitConfigInvalid)
	}
	if p.lockFile != nil {
		t.Error("Program kept a lock after a failed start")
	}
	lf := lockfile.NewLockFileWithPath(lockPath)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("lock not released after a failed start: %v", err)
	}
	_ = lf.Release()
}

func TestProgramStart_LockFileUnusable(t *testing.T) {
	_, cfg := useTempLock(t)
	missing := filepath.Join(t.TempDir(), "missing", lockName+".lock")
	newProcessLock = func() *lockfile.LockFile { return lockfile.NewLockFileWithPath(missing) }

	err := NewProgram(cfg).Start(nil)
	if code := StartExitCode(err); code != ExitLockError {
		t.Errorf("StartExitCode(%v) = %d, want %d", err, code, ExitLockError)
	}
}

func TestStartExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want uint32
	}{
		{"already running", fmt.Errorf("wrapped: %w", lockfile.ErrAlreadyRunning), ExitAlreadyRunning},
		{"lock permission", fmt.Errorf("%w: %w", errProcessLock, fs.ErrPermission), ExitLockError},
		{"config load", fmt.Errorf("%w: %w", errConfigLoad, fs.ErrNotExist), ExitConfigInvalid},
		{"config invalid", fmt.Errorf("main integration failed to start: %w", fmt.Errorf("%w: x", internal.ErrConfigInvalid)), ExitConfigInvalid},
		{"scheduler", errors.New("failed to start scheduler: boom"), ExitStartupFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StartExitCode(tt.err); got != tt.want {
				t.Errorf("StartExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
