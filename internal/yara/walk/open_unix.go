//go:build linux || darwin

package walk

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open opens f read-only without side effects for the worker: it never
// follows a link (O_NOFOLLOW), can't block on a FIFO swapped in
// (O_NONBLOCK), doesn't update the access time where the kernel allows
// (O_NOATIME on Linux), and checks the opened file is the regular file the
// walk listed.
func Open(f File) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Open(f.Path, flags|noatime, 0)
	if err == unix.EPERM && noatime != 0 {
		// O_NOATIME needs the file's owner or CAP_FOWNER.
		fd, err = unix.Open(f.Path, flags, 0)
	}
	if err != nil {
		if err == unix.ELOOP {
			return nil, ErrChanged
		}
		return nil, &os.PathError{Op: "open", Path: f.Path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: f.Path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG ||
		(f.id != fileID{} && (uint64(st.Dev) != f.id.dev || st.Ino != f.id.ino)) { // #nosec G115 -- device numbers are never negative
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s", ErrChanged, f.Path)
	}
	return os.NewFile(uintptr(fd), f.Path), nil // #nosec G115 -- a valid descriptor is non-negative
}
