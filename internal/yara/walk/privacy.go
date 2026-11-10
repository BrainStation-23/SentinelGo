package walk

import (
	"errors"
	"syscall"
)

// privacyDenied reports whether err is macOS refusing access for privacy
// (TCC): without Full Disk Access a root service gets EPERM on ~/Downloads,
// ~/Desktop, ~/Documents and others, where ordinary permissions give
// EACCES. The fix is a PPPC profile granting the agent Full Disk Access.
func privacyDenied(goos string, err error) bool {
	return goos == "darwin" && errors.Is(err, syscall.EPERM)
}
