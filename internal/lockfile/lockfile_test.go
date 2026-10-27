package lockfile_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sentinelgo/internal/lockfile"
)

// helperEnv makes the test binary act as a second process that holds the lock
// at the given path (see TestMain).
const helperEnv = "SENTINELGO_LOCKFILE_HELPER_PATH"

// TestMain lets a test re-exec this binary as a lock holder: it acquires the
// lock, prints "locked", and releases it when its stdin is closed.
func TestMain(m *testing.M) {
	if path := os.Getenv(helperEnv); path != "" {
		os.Exit(runHelper(path))
	}
	os.Exit(m.Run())
}

func runHelper(path string) int {
	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Println("locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := lf.Release(); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	return 0
}

// holder is a lock held by another process.
type holder struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func startHolder(t *testing.T, path string) *holder {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// #nosec G204 - re-executes this test binary
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	h := &holder{cmd: cmd, stdin: stdin}
	t.Cleanup(func() {
		_ = h.stdin.Close()
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	})

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper did not take the lock: %q, %v", line, err)
	}
	return h
}

// release asks the holder to release the lock and waits for it to exit.
func (h *holder) release(t *testing.T) {
	t.Helper()
	_ = h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("helper exited with error: %v", err)
	}
}

// kill ends the holder without letting it release the lock.
func (h *holder) kill(t *testing.T) {
	t.Helper()
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_ = h.cmd.Wait()
}

func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.lock")
}

func mustAcquire(t *testing.T, path string) *lockfile.LockFile {
	t.Helper()
	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}
	t.Cleanup(func() { _ = lf.Release() })
	return lf
}

func TestTryAcquire_HeldByAnotherProcess(t *testing.T) {
	path := lockPath(t)
	startHolder(t, path)

	err := lockfile.NewLockFileWithPath(path).TryAcquire()
	if !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Fatalf("TryAcquire() = %v, want ErrAlreadyRunning", err)
	}
}

func TestTryAcquire_AfterOtherProcessReleases(t *testing.T) {
	path := lockPath(t)
	startHolder(t, path).release(t)

	mustAcquire(t, path)
}

func TestTryAcquire_AfterOtherProcessIsKilled(t *testing.T) {
	path := lockPath(t)
	startHolder(t, path).kill(t)

	// The OS drops the lock when the holder dies; no cleanup or wait needed.
	mustAcquire(t, path)
}

// TestTryAcquire_StalePIDOfLiveProcess is the regression test for #242: a
// leftover file naming a live, unrelated process must not block a start.
func TestTryAcquire_StalePIDOfLiveProcess(t *testing.T) {
	path := lockPath(t)
	for _, pid := range []int{os.Getppid(), os.Getpid()} {
		if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0600); err != nil {
			t.Fatalf("write stale lock: %v", err)
		}
		lf := lockfile.NewLockFileWithPath(path)
		if err := lf.TryAcquire(); err != nil {
			t.Fatalf("TryAcquire() with stale PID %d: %v", pid, err)
		}
		if err := lf.Release(); err != nil {
			t.Fatalf("Release(): %v", err)
		}
	}
}

func TestTryAcquire_LeftoverFileContents(t *testing.T) {
	for name, content := range map[string]string{
		"empty":   "",
		"garbage": "not-a-pid\x00\xff",
	} {
		t.Run(name, func(t *testing.T) {
			path := lockPath(t)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatalf("write leftover lock: %v", err)
			}
			mustAcquire(t, path)
		})
	}
}

func TestTryAcquire_HeldInSameProcess(t *testing.T) {
	path := lockPath(t)
	mustAcquire(t, path)

	err := lockfile.NewLockFileWithPath(path).TryAcquire()
	if !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Fatalf("second TryAcquire() = %v, want ErrAlreadyRunning", err)
	}
}

func TestTryAcquire_WritesPID(t *testing.T) {
	path := lockPath(t)
	// A longer leftover must be truncated, not partially overwritten.
	if err := os.WriteFile(path, []byte("123456789012\n"), 0600); err != nil {
		t.Fatalf("write leftover lock: %v", err)
	}
	mustAcquire(t, path)

	// Diagnostics must be able to read the PID while the lock is held.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lock file while held: %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), strconv.Itoa(os.Getpid()); got != want {
		t.Errorf("lock file contains %q, want %q", got, want)
	}
}

func TestTryAcquire_TwiceOnSameLockFile(t *testing.T) {
	path := lockPath(t)
	lf := lockfile.NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("first TryAcquire() failed: %v", err)
	}
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("second TryAcquire() on the holder should be a no-op, got: %v", err)
	}
	if err := lf.Release(); err != nil {
		t.Fatalf("Release() failed: %v", err)
	}

	// A single Release must free the lock: the second call leaked no handle.
	mustAcquire(t, path)
}

func TestRelease_KeepsFileAndIsIdempotent(t *testing.T) {
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
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Release() must leave the lock file in place: %v", err)
	}
}

func TestRelease_NotAcquired(t *testing.T) {
	path := lockPath(t)
	mustAcquire(t, path)

	other := lockfile.NewLockFileWithPath(path)
	if err := other.Release(); err != nil {
		t.Fatalf("Release() on a non-acquired lock: %v", err)
	}
	// The holder still holds it.
	if err := lockfile.NewLockFileWithPath(path).TryAcquire(); !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Errorf("TryAcquire() after a non-owner Release() = %v, want ErrAlreadyRunning", err)
	}
}

func TestTryAcquire_MissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "test.lock")
	err := lockfile.NewLockFileWithPath(path).TryAcquire()
	if err == nil {
		t.Fatal("TryAcquire() in a missing directory should fail")
	}
	if errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Errorf("a missing directory must not be reported as a held lock: %v", err)
	}
}

func TestTryAcquire_PathIsDirectory(t *testing.T) {
	path := lockPath(t)
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err := lockfile.NewLockFileWithPath(path).TryAcquire()
	if err == nil {
		t.Fatal("TryAcquire() on a directory path should fail")
	}
	if errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Errorf("a directory must not be reported as a held lock: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Errorf("directory at lock path should be left intact, stat err=%v", err)
	}
}

func TestPath(t *testing.T) {
	path := lockPath(t)
	if got := lockfile.NewLockFileWithPath(path).Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}
