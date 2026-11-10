//go:build !windows && !darwin

package packages

import (
	"io/fs"

	"golang.org/x/sys/unix"
)

// placeholder: Linux has no cloud placeholder files; FUSE sync clients are
// excluded as non-local file systems.
func placeholder(fs.FileInfo) bool { return false }

// Network and FUSE file systems (statfs f_type), never walked.
var remoteFS = map[int64]bool{
	0x6969:     true, // NFS
	0x517B:     true, // SMB
	0xFF534D42: true, // CIFS
	0xFE534D42: true, // SMB2
	0x65735546: true, // FUSE (sshfs, rclone, gvfs, sync clients)
	0x564C:     true, // NCP
	0x7461636F: true, // OCFS2
	0x47504653: true, // GPFS
	0x19830326: true, // fhgfs / BeeGFS
	0x013111A8: true, // IBRIX
	0x6B414653: true, // AFS
	0x5346414F: true, // OpenAFS
	0x0BD00BD0: true, // Lustre
	0x00C36400: true, // CephFS
}

// localFS reports whether path is on a local file system.
func localFS(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return !remoteFS[int64(st.Type)] // #nosec G115 -- f_type is a magic number
}

// skipPlatformDir: nothing beyond the shared list on Linux.
func skipPlatformDir(string) bool { return false }
