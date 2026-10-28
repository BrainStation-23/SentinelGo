//go:build linux || darwin

package session

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// AcquireHelperLock makes this the only helper for the user (an flock in the
// user's runtime dir, else the temp dir). ok is false when another helper
// holds it; release frees it.
func AcquireHelperLock() (release func(), ok bool, err error) {
	dir := os.Getenv("XDG_RUNTIME_DIR") // per user, 0700
	if dir == "" {
		dir = os.TempDir() // per user on macOS
	}
	path := filepath.Join(dir, "sentinelgo-dlp-"+strconv.Itoa(os.Getuid())+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 G703 -- fixed file name in the user's own runtime dir (XDG_RUNTIME_DIR or the per-user temp dir)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() { _ = f.Close() }, true, nil
}
