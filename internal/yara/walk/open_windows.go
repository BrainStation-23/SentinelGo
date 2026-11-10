package walk

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// reparseTagNameSurrogate marks reparse tags that name another file
// (symlinks, junctions, mount points); other tags (cloud files, dedup)
// keep the file's own content behind a filter.
const reparseTagNameSurrogate = 0x20000000

// Open opens f read-only without side effects for the worker: backup
// semantics (the service reads files whatever their ACL says), sharing
// everything (a scan never locks a user out of a file), never through a
// link, and not updating the last access time. The opened handle must be a
// regular file, not a folder, link or cloud placeholder swapped in since
// the listing.
func Open(f File) (*os.File, error) {
	h, err := openHandle(f.Path, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return nil, err
	}
	info, err := handleInfo(h, f.Path)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|cloudAttributes) != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s", ErrChanged, f.Path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		// A local cloud file (OneDrive "always keep on this device") or a
		// deduplicated file: reopen through its filter to read the content,
		// and make sure it is still the same file.
		var tag struct{ FileAttributes, ReparseTag uint32 }
		err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo,
			(*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))) // #nosec G103 -- fixed-size struct for the API
		if err != nil || tag.ReparseTag&reparseTagNameSurrogate != 0 {
			_ = windows.CloseHandle(h)
			return nil, fmt.Errorf("%w: %s", ErrChanged, f.Path)
		}
		h2, err := openHandle(f.Path, 0)
		if err != nil {
			_ = windows.CloseHandle(h)
			return nil, err
		}
		info2, err := handleInfo(h2, f.Path)
		_ = windows.CloseHandle(h)
		if err != nil || info2.VolumeSerialNumber != info.VolumeSerialNumber ||
			info2.FileIndexHigh != info.FileIndexHigh || info2.FileIndexLow != info.FileIndexLow {
			_ = windows.CloseHandle(h2)
			return nil, fmt.Errorf("%w: %s", ErrChanged, f.Path)
		}
		h = h2
	}
	// All ones tells NTFS not to update the last access time for this
	// handle.
	keep := windows.Filetime{LowDateTime: 0xFFFFFFFF, HighDateTime: 0xFFFFFFFF}
	_ = windows.SetFileTime(h, nil, &keep, nil)
	return os.NewFile(uintptr(h), f.Path), nil
}

func openHandle(path string, extra uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_SEQUENTIAL_SCAN|extra, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return h, nil
}

func handleInfo(h windows.Handle, path string) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return info, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return info, nil
}
