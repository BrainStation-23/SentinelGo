package packages

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// sfDataless is st_flags' SF_DATALESS: an iCloud Drive or File Provider
// file whose content isn't on the Mac. Reading it downloads it.
const sfDataless = 0x40000000

// placeholder reports whether info is a dataless (cloud) file or folder.
func placeholder(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}

// localFS reports whether path is on a local file system (MNT_LOCAL), not
// SMB, NFS, AFP or WebDAV.
func localFS(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&unix.MNT_LOCAL != 0
}

// skipPlatformDir skips ~/Library: application data and caches, and
// Library/CloudStorage (File Provider folders), not projects.
func skipPlatformDir(name string) bool { return name == "Library" }
