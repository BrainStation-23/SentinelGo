//go:build !windows

package artifact

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// freeBytesForDir returns the number of free bytes on the volume containing dir.
func freeBytesForDir(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %q: %w", dir, err)
	}
	// Bavail is the number of free blocks available to unprivileged users.
	return st.Bavail * uint64(st.Bsize), nil //nolint:unconvert // Bsize is int64 on some platforms
}
