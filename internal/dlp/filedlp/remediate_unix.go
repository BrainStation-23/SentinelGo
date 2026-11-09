//go:build linux || darwin

package filedlp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sameFile checks that r.Path still names the scanned file (device and
// inode), so a file swapped in meanwhile is never moved or deleted.
func (m *remediator) sameFile(r Request) error {
	var st unix.Stat_t
	if err := unix.Lstat(r.Path, &st); err != nil {
		return errFileChanged
	}
	if uint64(st.Dev) != r.Ident.Dev || st.Ino != r.Ident.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG { // #nosec G115 -- device numbers
		return errFileChanged
	}
	return nil
}

// removeFile unlinks the file.
func (m *remediator) removeFile(r Request) error {
	if err := unix.Unlink(r.Path); err != nil {
		return fmt.Errorf("remove the file: %w", errnoOnly(err))
	}
	return nil
}
