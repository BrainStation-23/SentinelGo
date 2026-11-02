package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/enrollment"
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
	prevEnroll, prevIdentity, prevRetry, prevLater, prevExit := enroll, enrollIdentity, enrollRetry, tokenMayArriveLater, exitProcess
	newProcessLock = func() *lockfile.LockFile { return lockfile.NewLockFileWithPath(lockPath) }
	logger = nopLogger{}
	// No enrollment token anywhere, and none can arrive later: the config
	// is used as it is (the pre-#351 behaviour on every platform).
	enroll = func(context.Context, *config.Config, enrollment.Identity) error { return enrollment.ErrNoToken }
	enrollIdentity = func() enrollment.Identity { return enrollment.Identity{} }
	enrollRetry = func(int) time.Duration { return time.Millisecond }
	tokenMayArriveLater = false
	exitProcess = func(code int) { t.Errorf("exitProcess(%d) called unexpectedly", code) }
	t.Cleanup(func() {
		newProcessLock, logger = prevLock, prevLogger
		enroll, enrollIdentity, enrollRetry, tokenMayArriveLater, exitProcess = prevEnroll, prevIdentity, prevRetry, prevLater, prevExit
	})

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

// countingEnroll fails the first n attempts with err, then succeeds without
// changing the config (so the start that follows still fails validation).
func countingEnroll(n int, err error) (*int, *sync.Mutex) {
	var mu sync.Mutex
	calls := 0
	enroll = func(context.Context, *config.Config, enrollment.Identity) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls <= n {
			return err
		}
		return nil
	}
	return &calls, &mu
}

// Where a token can still arrive (macOS MDM), a service without one stays up
// and keeps trying; Stop ends the wait cleanly (#351).
func TestProgramStart_WaitsForEnrollmentToken(t *testing.T) {
	_, cfg := useTempLock(t)
	tokenMayArriveLater = true
	calls, mu := countingEnroll(1_000_000, enrollment.ErrNoToken)

	p := NewProgram(cfg)
	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() = %v, want the service up and waiting", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := *calls
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("enrollment tried %d times, want retries", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := p.Stop(nil); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mainIntegration != nil {
		t.Error("the agent started without being enrolled")
	}
}

// A failed exchange (the backend unreachable) waits on every platform, and
// once enrolled the agent starts; a start that then fails exits the process
// with the start's exit code so the service manager restarts it.
func TestProgramStart_EnrollThenStart(t *testing.T) {
	_, cfg := useTempLock(t)
	countingEnroll(2, errors.New("dial tcp: connection refused"))
	exited := make(chan int, 1)
	exitProcess = func(code int) { exited <- code }

	p := NewProgram(cfg)
	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() = %v, want the service up and retrying", err)
	}
	select {
	case code := <-exited:
		// The stub enrolls without filling the config, so validation fails.
		if code != int(ExitConfigInvalid) {
			t.Errorf("exit code %d, want %d", code, ExitConfigInvalid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never started after enrolling")
	}
	_ = p.Stop(nil)
}

// A config that already has an API URL never enrolls.
func TestProgramStart_ExistingInstallSkipsEnrollment(t *testing.T) {
	_, cfg := useTempLock(t)
	cfg.SupabaseURL = "https://api.example.com"
	enroll = func(context.Context, *config.Config, enrollment.Identity) error {
		t.Error("an existing install tried to enroll")
		return nil
	}
	_ = NewProgram(cfg).Start(nil) // fails validation (no key); that's fine here
}
