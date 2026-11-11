package walk

import (
	"os"
	"runtime"

	"sentinelgo/internal/userhomes"
)

// DefaultEnv is the running device's Env: its OS, users' home folders,
// environment and file system.
func DefaultEnv() Env {
	return Env{
		GOOS:        runtime.GOOS,
		Homes:       userhomes.Dirs(),
		Getenv:      os.Getenv,
		ReadDir:     os.ReadDir,
		FixedDrives: fixedDrives,
		Exists: func(p string) bool {
			_, err := os.Lstat(p)
			return err == nil
		},
	}
}
