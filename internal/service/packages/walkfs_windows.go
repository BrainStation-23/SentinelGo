package packages

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// Attributes of a file whose data isn't on the device (OneDrive, Dropbox
// and other cloud files-on-demand, HSM). Reading such a file downloads it.
const (
	fileAttributeOffline            = 0x00001000
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000
	cloudAttributes                 = fileAttributeOffline | fileAttributeRecallOnOpen | fileAttributeRecallOnDataAccess
)

// placeholder reports whether info is a cloud placeholder.
func placeholder(info fs.FileInfo) bool {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&cloudAttributes != 0
}

// localFS reports whether path is on a local drive: not a UNC path and not
// a mapped network drive.
func localFS(path string) bool {
	vol := filepath.VolumeName(path)
	if vol == "" || strings.HasPrefix(vol, `\\`) {
		return false
	}
	p, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return false
	}
	return windows.GetDriveType(p) != windows.DRIVE_REMOTE
}

// deviceOf: directory links aren't followed, so the walk can't reach
// another volume through a mount point; there is nothing more to check.
func deviceOf(fs.FileInfo) (uint64, bool) { return 0, false }

// skipPlatformDir skips AppData: application data, caches and the global
// npm and Python installs (reported as global already), not projects.
func skipPlatformDir(name string) bool { return strings.EqualFold(name, "AppData") }

// sameFold compares paths case-insensitively, as NTFS does.
func sameFold(a, b string) bool { return strings.EqualFold(a, b) }
