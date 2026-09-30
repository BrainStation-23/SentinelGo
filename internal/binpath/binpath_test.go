package binpath

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolve_UnknownNameReturnsUnchanged(t *testing.T) {
	got := Resolve("some-binary-with-no-known-candidates-xyz")
	if got != "some-binary-with-no-known-candidates-xyz" {
		t.Errorf("Resolve(unknown) = %q, want the name unchanged", got)
	}
}

func TestResolve_KnownNameFallsBackWhenCandidatesDontExist(t *testing.T) {
	// launchctl only exists on macOS; on any other host none of its
	// candidates exist, so Resolve must fall back to the bare name rather
	// than returning a nonexistent path.
	if runtime.GOOS == "darwin" {
		t.Skip("launchctl genuinely exists on darwin; covered by the exists-case test instead")
	}
	got := Resolve("launchctl")
	if got != "launchctl" {
		t.Errorf("Resolve(\"launchctl\") on %s = %q, want the bare name (no candidate exists)", runtime.GOOS, got)
	}
}

func TestResolve_ReturnsRealExistingCandidateOnThisHost(t *testing.T) {
	// Pick a binary this test process itself is proof exists: on Windows,
	// cmd.exe backs every subprocess call chain; on Unix, /bin/sh is used
	// by Go's os/exec internally for basically everything.
	var name, mustContain string
	switch runtime.GOOS {
	case "windows":
		name, mustContain = "cmd", "System32"
	default:
		name, mustContain = "sh", "/bin/sh"
	}

	got := Resolve(name)
	if got == name {
		t.Fatalf("Resolve(%q) = %q, want a resolved absolute path (candidate should exist on %s)", name, got, runtime.GOOS)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("Resolve(%q) = %q, want an absolute path", name, got)
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(got); err != nil {
			t.Errorf("resolved path %q does not exist: %v", got, err)
		}
	} else if got != mustContain {
		t.Errorf("Resolve(%q) = %q, want %q", name, got, mustContain)
	}
}

func TestWindowsSystemRoot_UsesEnvVar(t *testing.T) {
	t.Setenv("SystemRoot", `D:\CustomWindows`)
	if got := windowsSystemRoot(); got != `D:\CustomWindows` {
		t.Errorf("windowsSystemRoot() = %q, want %q", got, `D:\CustomWindows`)
	}
}

func TestWindowsSystemRoot_FallsBackWhenUnset(t *testing.T) {
	t.Setenv("SystemRoot", "")
	if got := windowsSystemRoot(); got != `C:\Windows` {
		t.Errorf("windowsSystemRoot() = %q, want default %q", got, `C:\Windows`)
	}
}
