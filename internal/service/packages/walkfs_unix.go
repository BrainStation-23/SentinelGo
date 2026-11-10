//go:build !windows

package packages

import (
	"io/fs"
	"syscall"
)

// deviceOf returns the file system a file is on, so the walk stays on the
// root's file system (no network mounts, removable media or /proc-like
// file systems mounted inside a home).
func deviceOf(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true // #nosec G115 -- Dev is a device number, never negative
}

// sameFold compares paths exactly (case-sensitive file systems; on macOS
// homes always have their canonical case).
func sameFold(a, b string) bool { return a == b }
