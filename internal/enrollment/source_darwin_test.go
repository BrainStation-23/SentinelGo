package enrollment

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// On macOS the token comes from MDM managed preferences.
func TestPlatformSource_ManagedPreferences(t *testing.T) {
	dir := t.TempDir()
	prevPath, prevRun := managedPrefs, runCommand
	t.Cleanup(func() { managedPrefs, runCommand = prevPath, prevRun })

	managedPrefs = filepath.Join(dir, "missing.plist")
	if _, err := platformSource(); !errors.Is(err, ErrNoToken) {
		t.Errorf("no profile: %v", err)
	}

	managedPrefs = filepath.Join(dir, "com.sentinelgo.agent.plist")
	if err := os.WriteFile(managedPrefs, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCommand = func(name string, args ...string) (string, error) {
		if name != "plutil" || args[len(args)-1] != managedPrefs {
			t.Errorf("ran %s %v", name, args)
		}
		return `{"EnrollmentToken":"tok","ServerURL":"https://api.example.com","AnonKey":"anon"}`, nil
	}
	src, err := platformSource()
	if err != nil || src.Token != "tok" || src.ServerURL != "https://api.example.com" || src.file != "" {
		t.Errorf("src %+v err %v", src, err)
	}

	runCommand = func(string, ...string) (string, error) { return `{"ServerURL":"https://x"}`, nil }
	if _, err := platformSource(); !errors.Is(err, ErrNoToken) {
		t.Errorf("profile without a token: %v", err)
	}
}
