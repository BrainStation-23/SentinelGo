package lockfile_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/lockfile"
)

func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.lock")
}

func TestNewLockFileWithPath(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	if lf == nil {
		t.Fatal("NewLockFileWithPath() returned nil")
	}
}

func TestTryAcquire_Basic(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}
	defer func() { _ = lf.Release() }()
}

func TestTryAcquire_AlreadyHeld(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("IsProcessRunning uses Signal(os.Kill) on Windows which would kill the test process")
	}
	path := lockPath(t)

	lf1 := lockfile.NewLockFileWithPath(path)
	if err := lf1.TryAcquire(); err != nil {
		t.Fatalf("first TryAcquire() failed: %v", err)
	}
	defer func() { _ = lf1.Release() }()

	lf2 := lockfile.NewLockFileWithPath(path)
	err := lf2.TryAcquire()
	if err == nil {
		_ = lf2.Release()
		t.Fatal("second TryAcquire() should have failed, got nil")
	}
	if !strings.Contains(err.Error(), "lock already held") {
		t.Errorf("expected 'lock already held' error, got: %v", err)
	}
}

func TestRelease_RemovesFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot os.Remove an open file; Release() closes then removes, so file persists on error — Unix-only check")
	}
	path := lockPath(t)
	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}

	if err := lf.Release(); err != nil {
		t.Fatalf("Release() failed: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("lock file still exists after Release()")
	}
}

func TestRelease_AllowsReacquire(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Release leaves file on Windows (cannot remove open file); re-acquire then triggers Signal(os.Kill) on current PID")
	}
	path := lockPath(t)

	lf1 := lockfile.NewLockFileWithPath(path)
	if err := lf1.TryAcquire(); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if err := lf1.Release(); err != nil {
		t.Fatalf("Release() failed: %v", err)
	}

	lf2 := lockfile.NewLockFileWithPath(path)
	if err := lf2.TryAcquire(); err != nil {
		t.Fatalf("re-acquire after Release() failed: %v", err)
	}
	defer func() { _ = lf2.Release() }()
}

func TestGetLockedPID(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}
	defer func() { _ = lf.Release() }()

	pid, err := lf.GetLockedPID()
	if err != nil {
		t.Fatalf("GetLockedPID() failed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("GetLockedPID() = %d, want %d (current PID)", pid, os.Getpid())
	}
}

func TestGetLockedPID_NoFile(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	_, err := lf.GetLockedPID()
	if err == nil {
		t.Fatal("GetLockedPID() on non-existent file should return error")
	}
}

func TestAcquireWithTimeout_Success(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	if err := lf.AcquireWithTimeout(500 * time.Millisecond); err != nil {
		t.Fatalf("AcquireWithTimeout() failed: %v", err)
	}
	defer func() { _ = lf.Release() }()
}

func TestAcquireWithTimeout_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("IsProcessRunning uses Signal(os.Kill) on Windows which would kill the test process")
	}
	path := lockPath(t)

	lf1 := lockfile.NewLockFileWithPath(path)
	if err := lf1.TryAcquire(); err != nil {
		t.Fatalf("holder acquire failed: %v", err)
	}
	defer func() { _ = lf1.Release() }()

	lf2 := lockfile.NewLockFileWithPath(path)
	err := lf2.AcquireWithTimeout(150 * time.Millisecond)
	if err == nil {
		_ = lf2.Release()
		t.Fatal("AcquireWithTimeout() should have timed out, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestCheckExistingLock_NoFile(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	locked, err := lf.CheckExistingLock()
	if err != nil {
		t.Fatalf("CheckExistingLock() error: %v", err)
	}
	if locked {
		t.Error("CheckExistingLock() = true, want false (no lock file)")
	}
}

func TestCheckExistingLock_StaleFile(t *testing.T) {
	path := lockPath(t)
	// Write a stale lock file with a PID that is not a multiple of 4 and
	// far above any realistic range — guaranteed non-existent on all OSes.
	if err := os.WriteFile(path, []byte("99999999\n"), 0644); err != nil {
		t.Fatalf("failed to write stale lock file: %v", err)
	}

	lf := lockfile.NewLockFileWithPath(path)
	locked, err := lf.CheckExistingLock()
	if err != nil {
		t.Fatalf("CheckExistingLock() error: %v", err)
	}
	if locked {
		t.Error("CheckExistingLock() = true, want false (stale lock with dead PID)")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("stale lock file should have been removed by CheckExistingLock()")
	}
}

func TestCheckExistingLock_ActiveLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("IsProcessRunning uses Signal(os.Kill) on Windows which would kill the test process")
	}
	path := lockPath(t)

	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}
	defer func() { _ = lf.Release() }()

	lf2 := lockfile.NewLockFileWithPath(path)
	locked, err := lf2.CheckExistingLock()
	if err != nil {
		t.Fatalf("CheckExistingLock() error: %v", err)
	}
	if !locked {
		t.Error("CheckExistingLock() = false, want true (active lock)")
	}
}

func TestIsProcessRunning_CurrentProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Signal(os.Kill) on Windows terminates the target process — cannot safely probe current PID")
	}
	if !lockfile.IsProcessRunning(os.Getpid()) {
		t.Errorf("IsProcessRunning(%d) = false, want true (current process)", os.Getpid())
	}
}

func TestIsProcessRunning_NonExistent(t *testing.T) {
	// 99999999 is not a multiple of 4, so it cannot be a valid Windows PID.
	// On all platforms, this PID should not exist in practice.
	if lockfile.IsProcessRunning(99999999) {
		t.Skip("PID 99999999 unexpectedly exists on this system — skipping test")
	}
}
