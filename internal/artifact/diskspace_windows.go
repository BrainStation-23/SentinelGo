//go:build windows

package artifact

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// freeBytesForDir returns the number of free bytes on the volume containing dir.
func freeBytesForDir(dir string) (uint64, error) {
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, fmt.Errorf("encode dir path: %w", err)
	}
	if err := windows.GetDiskFreeSpaceEx(dirPtr, &freeBytesAvailable, &totalBytes, &totalFreeBytes); err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %q: %w", dir, err)
	}
	return freeBytesAvailable, nil
}
