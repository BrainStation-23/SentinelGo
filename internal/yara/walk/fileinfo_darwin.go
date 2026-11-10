package walk

import (
	"io/fs"
	"syscall"
)

// sfDataless is st_flags' SF_DATALESS: an iCloud Drive or File Provider
// file whose content isn't on the Mac. Reading it downloads it.
const sfDataless = 0x40000000

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
		k.Change = st.Ctimespec.Nano()
	}
	return k
}

func placeholder(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
