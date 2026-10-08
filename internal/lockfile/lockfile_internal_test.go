package lockfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewLockFile_Path(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		// Redirect the home directory so the test never touches the real
		// profile; NewLockFile creates <home>\.sentinelgo.
		home := t.TempDir()
		t.Setenv("USERPROFILE", home)

		lf := NewLockFile("testservice")
		want := filepath.Join(home, ".sentinelgo", "testservice.lock")
		if lf.path != want {
			t.Errorf("path = %q, want %q", lf.path, want)
		}
		if fi, err := os.Stat(filepath.Dir(want)); err != nil || !fi.IsDir() {
			t.Errorf("lock directory not created: %v", err)
		}
	case "linux", "darwin":
		// The directory is fixed under /opt; only check the computed path.
		// NewLockFile ignores MkdirAll failures, so this is safe as non-root.
		lf := NewLockFile("testservice")
		want := filepath.Join("/opt/sentinelgo/.sentinelgo", "testservice.lock")
		if lf.path != want {
			t.Errorf("path = %q, want %q", lf.path, want)
		}
	default:
		t.Skipf("no expectation for GOOS=%s", runtime.GOOS)
	}
}

func TestRelease_ToleratesCloseAndRemoveErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.lock")
	lf := NewLockFileWithPath(path)
	if err := lf.TryAcquire(); err != nil {
		t.Fatalf("TryAcquire() failed: %v", err)
	}

	// Force both best-effort steps to fail: the file is already closed, and
	// the path no longer exists.
	if err := lf.file.Close(); err != nil {
		t.Fatalf("pre-close: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("pre-remove: %v", err)
	}

	if err := lf.Release(); err != nil {
		t.Fatalf("Release() should swallow close/remove errors, got: %v", err)
	}
	if lf.acquired || lf.file != nil {
		t.Errorf("Release() left state acquired=%v file=%v", lf.acquired, lf.file)
	}
}
