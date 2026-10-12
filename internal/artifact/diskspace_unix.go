//go:build unix

package artifact

import "golang.org/x/sys/unix"

// freeBytes returns the bytes available to an unprivileged user on the
// volume holding dir.
func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil // #nosec G115 - block size is positive
}
