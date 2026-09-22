package paths_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sentinelgo/internal/paths"
)

// TestRootsAreAbsoluteAndDistinct checks the invariants every caller relies on:
// an empty or relative root would silently scatter agent state through whatever
// the working directory happens to be.
func TestRootsAreAbsoluteAndDistinct(t *testing.T) {
	roots := map[string]string{
		"InstallDir":     paths.InstallDir(),
		"DataDir":        paths.DataDir(),
		"StagingDir":     paths.StagingDir(),
		"ConfigPath":     paths.ConfigPath(),
		"TaskDBPath":     paths.TaskDBPath(),
		"ServicesDBPath": paths.ServicesDBPath(),
		"CheckpointPath": paths.CheckpointPath(),
		"LockPath":       paths.LockPath("sentinelgo"),
	}

	for name, p := range roots {
		if p == "" {
			t.Errorf("%s() is empty", name)
			continue
		}
		if !filepath.IsAbs(p) {
			t.Errorf("%s() = %q, want an absolute path", name, p)
		}
	}

	if paths.InstallDir() == paths.DataDir() {
		t.Error("InstallDir and DataDir must differ: the binary directory and the " +
			"credential directory need different access rules")
	}
}

// TestStateFilesLiveInDataDir pins every mutable file to the one directory the
// hardening logic secures. The lock file in particular used to sit under
// %USERPROFILE%, outside anything the ACL code touched.
func TestStateFilesLiveInDataDir(t *testing.T) {
	data := paths.DataDir()

	for name, p := range map[string]string{
		"ConfigPath":     paths.ConfigPath(),
		"TaskDBPath":     paths.TaskDBPath(),
		"ServicesDBPath": paths.ServicesDBPath(),
		"CheckpointPath": paths.CheckpointPath(),
		"LockPath":       paths.LockPath("sentinelgo"),
	} {
		if got := filepath.Dir(p); !strings.EqualFold(got, data) {
			t.Errorf("%s() lives in %q, want it inside DataDir %q", name, got, data)
		}
	}
}

// TestStagingDirIsBesideTheBinary matters for correctness, not just tidiness:
// the update swap renames the staged binary over the running one, and a rename
// cannot cross volumes.
func TestStagingDirIsBesideTheBinary(t *testing.T) {
	if got, want := filepath.Dir(paths.StagingDir()), paths.InstallDir(); got != want {
		t.Errorf("StagingDir parent = %q, want InstallDir %q", got, want)
	}
	if !paths.IsManagedPath(paths.StagingDir()) {
		t.Error("StagingDir must be a managed path: update artifacts are executable " +
			"and have to be hardened")
	}
}

func TestIsManagedPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"install dir itself", paths.InstallDir(), true},
		{"data dir itself", paths.DataDir(), true},
		{"config file", paths.ConfigPath(), true},
		{"staging dir", paths.StagingDir(), true},
		{"nested under data dir", filepath.Join(paths.DataDir(), "a", "b", "c.json"), true},
		{"empty", "", false},
		{"relative", "config.json", false},

		// The prefix-match trap: a sibling whose name merely starts with a
		// managed root must not be treated as managed. A naive
		// strings.HasPrefix would hand an attacker-created directory the
		// hardening path and, worse, report it as trusted.
		{"sibling with shared prefix", paths.DataDir() + "Evil", false},
		{"install sibling with shared prefix", paths.InstallDir() + "-backup", false},

		// Traversal must not escape detection.
		{"traversal out of data dir", filepath.Join(paths.DataDir(), "..", "elsewhere"), false},
		{"traversal back in", filepath.Join(paths.DataDir(), "..", filepath.Base(paths.DataDir()), "x"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paths.IsManagedPath(tt.path); got != tt.want {
				t.Errorf("IsManagedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsManagedPathCaseInsensitiveOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path comparison is case-insensitive; other platforms are not")
	}
	if !paths.IsManagedPath(strings.ToUpper(paths.ConfigPath())) {
		t.Error("IsManagedPath must be case-insensitive on Windows, or hardening " +
			"silently skips a path spelled with different casing")
	}
}
