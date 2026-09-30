//go:build windows

package software

import (
	"strings"
	"testing"
)

func TestPlatformUserHomeDirs_Windows_ReturnsAtLeastOwnHome(t *testing.T) {
	homes := platformUserHomeDirs()
	if len(homes) == 0 {
		t.Fatal("platformUserHomeDirs() returned no homes, want at least the current user's own home")
	}
}

func TestPlatformUserHomeDirs_Windows_SkipsNonUserProfiles(t *testing.T) {
	homes := platformUserHomeDirs()
	for _, h := range homes {
		for profile := range nonUserProfiles {
			if strings.HasSuffix(h, `\`+profile) {
				t.Errorf("platformUserHomeDirs() included non-user profile %q: %v", profile, h)
			}
		}
	}
}

func TestPlatformUserHomeDirs_Windows_ReadDirErrorFallsBackGracefully(t *testing.T) {
	// A nonexistent SystemDrive forces os.ReadDir(usersDir) to fail; the function
	// must return without panicking, falling back to just the service account's
	// own home (still discovered via os.UserHomeDir, which doesn't depend on
	// SystemDrive).
	t.Setenv("SystemDrive", "Z:")
	homes := platformUserHomeDirs()
	if homes == nil {
		t.Error("platformUserHomeDirs() = nil, want a non-nil (possibly single-element) slice on ReadDir failure")
	}
}
