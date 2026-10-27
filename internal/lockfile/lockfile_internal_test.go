package lockfile

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestNewLockFile_Path checks the lock lives in one fixed directory per OS,
// not under the account's home directory (#242). NewLockFile ignores MkdirAll
// failures, so this is safe without admin rights.
func TestNewLockFile_Path(t *testing.T) {
	var want string
	switch runtime.GOOS {
	case "windows":
		want = `C:\SentinelGo\.sentinelgo\sentinelgo.lock`
	case "linux", "darwin":
		want = "/opt/sentinelgo/.sentinelgo/sentinelgo.lock"
	default:
		t.Skipf("no expectation for GOOS=%s", runtime.GOOS)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	if got := NewLockFile("sentinelgo").path; filepath.Clean(got) != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}
