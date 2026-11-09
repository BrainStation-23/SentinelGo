package filedlp

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileDispositionInfo is FILE_DISPOSITION_INFO's class (the pre-Ex one,
// which FAT and exFAT accept).
const fileDispositionInfo = 4

// sameFile checks that the handle the hook holds is still the scanned file
// and version. The handle was opened without write sharing, so nobody could
// change it since; this catches a handle that went stale (drive removed).
func (m *remediator) sameFile(r Request) error {
	id, err := handleIdentity(windows.Handle(r.File.Fd()))
	if err != nil || id.Dev != r.Ident.Dev || id.Ino != r.Ident.Ino || id.Size != r.Ident.Size {
		return errFileChanged
	}
	return nil
}

// removeFile deletes the file through the handle the hook holds (opened with
// DELETE access), so it can only ever delete the file that was scanned, even
// if it was renamed meanwhile. NTFS removes the name at once (POSIX
// semantics); FAT and exFAT when the last handle closes, right after.
func (m *remediator) removeFile(r Request) error {
	h := windows.Handle(r.File.Fd())
	ex := struct{ Flags uint32 }{windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE}
	err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&ex)), uint32(unsafe.Sizeof(ex)))
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("remove the file: %w", err)
	}
	// File systems without the Ex class (FAT, exFAT, older Windows).
	del := struct{ Delete byte }{1}
	if err := windows.SetFileInformationByHandle(h, fileDispositionInfo, &del.Delete, 1); err != nil {
		return fmt.Errorf("remove the file: %w", err)
	}
	return nil
}

// fileBasicInfo is FILE_BASIC_INFO.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

// handleIdentity is a file's identity and version: the volume serial and
// file index (stable for the file's life on NTFS, FAT and exFAT), size and
// times (Unix ns).
func handleIdentity(h windows.Handle) (Identity, error) {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return Identity{}, err
	}
	id := Identity{
		Dev:     uint64(fi.VolumeSerialNumber),
		Ino:     uint64(fi.FileIndexHigh)<<32 | uint64(fi.FileIndexLow),
		Size:    int64(uint64(fi.FileSizeHigh)<<32 | uint64(fi.FileSizeLow)), // #nosec G115 -- a file size
		ModTime: fi.LastWriteTime.Nanoseconds(),
	}
	var bi fileBasicInfo
	if windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi))) == nil {
		ft := windows.Filetime{LowDateTime: uint32(bi.ChangeTime), HighDateTime: uint32(bi.ChangeTime >> 32)} // #nosec G115 -- a FILETIME's halves
		id.ChangeTime = ft.Nanoseconds()
	}
	return id, nil
}
