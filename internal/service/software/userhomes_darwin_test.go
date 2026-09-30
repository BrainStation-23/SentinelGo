//go:build darwin

package software

import (
	"testing"
)

func TestPlatformUserHomeDirs_Darwin_ReturnsAtLeastOwnHome(t *testing.T) {
	// CI runners genuinely have /Users and a real service-account home, so this
	// exercises the actual os.UserHomeDir + /Users read-dir loop without mocking.
	homes := platformUserHomeDirs()
	if len(homes) == 0 {
		t.Fatal("platformUserHomeDirs() returned no homes, want at least the current user's own home")
	}
}

func TestPlatformUserHomeDirs_Darwin_SkipsNonUserHomes(t *testing.T) {
	homes := platformUserHomeDirs()
	for _, h := range homes {
		for skip := range nonUserHomes {
			if h == "/Users/"+skip {
				t.Errorf("platformUserHomeDirs() included non-user home %q", h)
			}
		}
	}
}

func TestPlatformUserHomeDirs_Darwin_NoDuplicates(t *testing.T) {
	homes := platformUserHomeDirs()
	seen := make(map[string]bool, len(homes))
	for _, h := range homes {
		if seen[h] {
			t.Errorf("platformUserHomeDirs() returned duplicate entry %q", h)
		}
		seen[h] = true
	}
}
