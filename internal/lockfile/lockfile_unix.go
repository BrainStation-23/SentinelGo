//go:build !windows

package lockfile

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockDir is the lock directory on Linux and macOS, next to config.json.
func lockDir() string {
	return "/opt/sentinelgo/.sentinelgo"
}

// openLocked opens (creating if needed) the lock file and takes an exclusive,
// non-blocking flock on it. Go opens files with O_CLOEXEC, so exec'd children
// don't inherit the descriptor and can't keep the lock alive.
func openLocked(path string) (*os.File, error) {
	// #nosec G302 G304 - fixed lock path; world-readable so diagnostics can read the PID
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", path, err)
	}
	// #nosec G115 - a file descriptor always fits in an int
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("failed to lock %s: %w", path, err)
	}
	return f, nil
}
