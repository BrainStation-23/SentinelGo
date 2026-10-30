//go:build linux || darwin

package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGrantUserExec(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sentinelgo")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "sentinelgo")
	if err := os.WriteFile(exe, nil, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { // past the umask
		t.Fatal(err)
	}
	if err := grantUserExec(exe); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, exe} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o755 {
			t.Errorf("%s mode = %04o, want 0755 (r-x for others, no write)", p, got)
		}
	}
}

func TestUserCanReach(t *testing.T) {
	sh, err := sysTool("sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := userCanReach(sh); err != nil {
		t.Errorf("userCanReach(%s) = %v, want nil", sh, err)
	}

	dir := filepath.Join(t.TempDir(), "sentinelgo")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "sentinelgo")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := userCanReach(exe); err == nil {
		t.Errorf("userCanReach under a 0700 directory = nil, want an error")
	}
}
