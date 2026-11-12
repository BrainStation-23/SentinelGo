//go:build !linux && !darwin && !windows

package walk

import "io/fs"

type fileID struct{}

func idOf(fs.FileInfo) fileID { return fileID{} }

func keyOf(path string, info fs.FileInfo) Key {
	return Key{Path: path, Size: info.Size(), MTime: info.ModTime().UnixNano()}
}

func placeholder(fs.FileInfo) bool { return false }
