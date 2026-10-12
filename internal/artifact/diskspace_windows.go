//go:build windows

package artifact

import "golang.org/x/sys/windows"

// freeBytes returns the bytes available to this process's account on the
// volume holding dir (quota-aware).
func freeBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err != nil {
		return 0, err
	}
	return avail, nil
}
