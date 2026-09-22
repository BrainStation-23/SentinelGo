//go:build windows

package winsec

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateSecureFile creates path for writing with a protected SYSTEM+Administrators
// DACL already applied, failing if the path already exists.
//
// The distinction from "create, then call SecureSystemPath" is not cosmetic. The
// updater used to open the staged binary with a default descriptor, download
// several megabytes into it, and only then fix the ACL -- leaving the whole
// download window open for a local attacker to overwrite an artifact that a
// LocalSystem service was about to execute. Passing the descriptor to CreateFile
// closes that window instead of shortening it: the file is never, at any
// instant, more permissive than intended.
//
// Three flags carry their own weight:
//
//   - CREATE_NEW: a pre-planted file causes ERROR_FILE_EXISTS rather than being
//     adopted and retroactively "secured". Callers must remove stale artifacts
//     deliberately, so an unexpected one is treated as hostile.
//   - FILE_SHARE_NONE: nothing else may hold the file open while we write it.
//   - FILE_FLAG_OPEN_REPARSE_POINT: a planted junction or symlink at this name
//     is not followed, so a privileged write cannot be redirected elsewhere.
func CreateSecureFile(path string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(systemFileDACL)
	if err != nil {
		return nil, fmt.Errorf("parse SDDL: %w", err)
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE|windows.DELETE,
		0, // FILE_SHARE_NONE
		&sa,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	// sa holds a pointer to sd; keep sd alive across the syscall.
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, fmt.Errorf("create secure file %s: %w", path, err)
	}

	return os.NewFile(uintptr(handle), path), nil
}
