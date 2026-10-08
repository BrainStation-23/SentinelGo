package lockfile_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

func TestTryAcquire_StaleLock(t *testing.T) {
	path := lockPath(t)
	if err := os.WriteFile(path, []byte("99999999\n"), 0644); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}

	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire with stale lock should succeed, got: %v", err)
	}
	defer func() { _ = lf.Release() }()
}

func TestRelease_NotAcquired(t *testing.T) {
	lf := lockfile.NewLockFileWithPath(lockPath(t))
	if err := lf.Release(); err != nil {
		t.Fatalf("Release() on non-acquired lock should not error: %v", err)
	}
}

func TestIsProcessRunning_CurrentProcess(t *testing.T) {
	if !lockfile.IsProcessRunning(os.Getpid()) {
		t.Errorf("IsProcessRunning(%d) = false, want true (current process)", os.Getpid())
	}
}

func TestIsProcessRunning_ExitedProcess(t *testing.T) {
	// Start a short-lived child, wait for it to exit, then confirm the probe
	// reports it as not running — and critically, never terminates anything.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit", "0")
	} else {
		cmd = exec.Command("true")
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start helper process: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait() // ensure it has fully exited

	if lockfile.IsProcessRunning(pid) {
		t.Errorf("IsProcessRunning(%d) = true, want false (exited process)", pid)
	}
}

func TestIsProcessRunning_NonExistent(t *testing.T) {
	// 99999999 is not a multiple of 4, so it cannot be a valid Windows PID.
	// On all platforms, this PID should not exist in practice.
	if lockfile.IsProcessRunning(99999999) {
		t.Skip("PID 99999999 unexpectedly exists on this system — skipping test")
	}
}

func TestTryAcquire_InvalidPIDContentIsStale(t *testing.T) {
	path := lockPath(t)
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire with unparseable lock content should succeed, got: %v", err)
	}
	defer func() { _ = lf.Release() }()

	pid, err := lf.GetLockedPID()
	if err != nil {
		t.Fatalf("GetLockedPID() failed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("GetLockedPID() = %d, want %d", pid, os.Getpid())
	}
}

func TestTryAcquire_ExitedProcessLockIsReclaimed(t *testing.T) {
	pid := exitedPID(t)
	path := lockPath(t)
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire over lock of exited PID %d should succeed, got: %v", pid, err)
	}
	defer func() { _ = lf.Release() }()
}

func TestTryAcquire_MissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "test.lock")
	lf := lockfile.NewLockFileWithPath(path)
	err := lf.TryAcquire()
	if err == nil {
		_ = lf.Release()
		t.Fatal("TryAcquire() in a missing directory should fail")
	}
	if !strings.Contains(err.Error(), "failed to create lock file") {
		t.Errorf("expected 'failed to create lock file' error, got: %v", err)
	}
	if strings.Contains(err.Error(), "lock already held") {
		t.Errorf("missing directory must not be reported as a held lock: %v", err)
	}
	// AcquireWithTimeout must return such non-contention errors immediately.
	start := time.Now()
	if err := lf.AcquireWithTimeout(5 * time.Second); err == nil {
		_ = lf.Release()
		t.Fatal("AcquireWithTimeout() in a missing directory should fail")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("AcquireWithTimeout() retried a non-contention error for %v", elapsed)
	}
}

func TestTryAcquire_PathIsNonEmptyDirectory(t *testing.T) {
	// A non-empty directory at the lock path: it cannot be read as a PID (so it
	// looks stale), cannot be removed, and blocks O_EXCL creation. TryAcquire
	// must fail rather than claim the lock.
	path := lockPath(t)
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0600); err != nil {
		t.Fatalf("write child: %v", err)
	}

	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err == nil {
		_ = lf.Release()
		t.Fatal("TryAcquire() on a directory path should fail")
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Errorf("directory at lock path should be left intact, stat err=%v", err)
	}
}

func TestRelease_Idempotent(t *testing.T) {
	path := lockPath(t)
	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}
	if err := lf.Release(); err != nil {
		t.Fatalf("first Release() failed: %v", err)
	}
	if err := lf.Release(); err != nil {
		t.Fatalf("second Release() should be a no-op, got: %v", err)
	}
}

func TestRelease_DoesNotRemoveForeignLock(t *testing.T) {
	// A LockFile that never acquired must not delete a lock held by another.
	path := lockPath(t)
	holder := lockfile.NewLockFileWithPath(path)
	if err := holder.TryAcquire(); err != nil {
		t.Fatalf("holder acquire failed: %v", err)
	}
	defer func() { _ = holder.Release() }()

	other := lockfile.NewLockFileWithPath(path)
	if err := other.Release(); err != nil {
		t.Fatalf("Release() on non-acquired lock: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("holder's lock file was removed by a non-owner Release(): %v", err)
	}
}

func TestGetLockedPID_InvalidContent(t *testing.T) {
	path := lockPath(t)
	if err := os.WriteFile(path, []byte("garbage"), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	lf := lockfile.NewLockFileWithPath(path)
	if _, err := lf.GetLockedPID(); err == nil || !strings.Contains(err.Error(), "invalid PID") {
		t.Errorf("GetLockedPID() error = %v, want 'invalid PID'", err)
	}
}

func TestCheckExistingLock_InvalidContent(t *testing.T) {
	path := lockPath(t)
	if err := os.WriteFile(path, []byte("garbage"), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	lf := lockfile.NewLockFileWithPath(path)
	locked, err := lf.CheckExistingLock()
	if err == nil {
		t.Fatal("CheckExistingLock() with unparseable content should return an error")
	}
	if locked {
		t.Error("CheckExistingLock() = true on error, want false")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("unparseable lock file should be left in place: %v", err)
	}
}

func TestCheckExistingLock_ExitedProcess(t *testing.T) {
	pid := exitedPID(t)
	path := lockPath(t)
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	lf := lockfile.NewLockFileWithPath(path)
	locked, err := lf.CheckExistingLock()
	if err != nil {
		t.Fatalf("CheckExistingLock() error: %v", err)
	}
	if locked {
		t.Errorf("CheckExistingLock() = true for exited PID %d", pid)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("lock of exited process should have been removed")
	}
}

func TestIsProcessRunning_NonPositivePID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if lockfile.IsProcessRunning(pid) {
			t.Errorf("IsProcessRunning(%d) = true, want false", pid)
		}
	}
}

// exitedPID starts a short-lived child, waits for it to exit and returns its
// PID. The PID could in principle be reused by the OS, so callers skip rather
// than fail if it is observed running again.
func exitedPID(t *testing.T) int {
	t.Helper()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit", "0")
	} else {
		cmd = exec.Command("true")
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start helper process: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	if lockfile.IsProcessRunning(pid) {
		t.Skipf("PID %d was reused before the test could use it", pid)
	}
	return pid
}
