package walk

import (
	"io/fs"
	"syscall"
)

type fileID struct{ dev, ino uint64 }

func idOf(info fs.FileInfo) fileID {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fileID{dev: uint64(st.Dev), ino: st.Ino} // #nosec G115 -- device numbers are never negative
	}
	return fileID{}
}

func keyOf(path string, info fs.FileInfo) Key {
	k := Key{Path: path, Size: info.Size(), MTime: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		k.Change = st.Ctim.Nano()
	}
	return k
}

// placeholder: Linux has no files-on-demand the walk could trigger.
func placeholder(fs.FileInfo) bool { return false }
