//go:build linux

package software

import "testing"

func TestPlatformUserHomeDirs_Linux_ReturnsAtLeastOwnHomeOrRoot(t *testing.T) {
	// CI runners genuinely have /root and a real service-account home, so this
	// exercises the actual os.UserHomeDir + /root + /home read-dir loop without
	// mocking. The exact contents are environment-dependent; we only assert it
	// doesn't panic and returns at least the guaranteed /root entry.
	homes := platformUserHomeDirs()
	if len(homes) == 0 {
		t.Fatal("platformUserHomeDirs() returned no homes, want at least /root")
	}

	found := false
	for _, h := range homes {
		if h == "/root" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("platformUserHomeDirs() = %v, want it to include /root", homes)
	}
}

func TestPlatformUserHomeDirs_Linux_NoDuplicates(t *testing.T) {
	homes := platformUserHomeDirs()
	seen := make(map[string]bool, len(homes))
	for _, h := range homes {
		if seen[h] {
			t.Errorf("platformUserHomeDirs() returned duplicate entry %q", h)
		}
		seen[h] = true
	}
}
