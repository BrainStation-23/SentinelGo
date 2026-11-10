package walk

import (
	"io/fs"
	"syscall"
)

// Attributes of a file whose data isn't on the device (OneDrive, Dropbox
// and other cloud files-on-demand, HSM). Reading such a file downloads it.
const (
	fileAttributeOffline            = 0x00001000
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000
	cloudAttributes                 = fileAttributeOffline | fileAttributeRecallOnOpen | fileAttributeRecallOnDataAccess
)

// fileID: a directory listing doesn't give Windows file ids; Open checks
// the opened handle instead.
type fileID struct{}

func idOf(fs.FileInfo) fileID { return fileID{} }

func keyOf(path string, info fs.FileInfo) Key {
	k := Key{Path: path, Size: info.Size(), MTime: info.ModTime().UnixNano()}
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		k.Change = d.CreationTime.Nanoseconds()
	}
	return k
}

func placeholder(info fs.FileInfo) bool {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&cloudAttributes != 0
}
