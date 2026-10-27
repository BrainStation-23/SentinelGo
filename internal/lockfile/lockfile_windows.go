//go:build windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sentinelgo/internal/config"

	"golang.org/x/sys/windows"
)

// lockDir is C:\SentinelGo\.sentinelgo, next to config.json. It used to be
// %USERPROFILE%\.sentinelgo, which is a different directory for LocalSystem
// (the service) and for an admin running -run, so the two never saw each
// other's lock, and the MSI never cleaned the service's copy up.
func lockDir() string {
	return filepath.Dir(config.WindowsConfigPath)
}

// openLocked opens (creating if needed) the lock file with read/write access
// while sharing read access only. Any other attempt to open it for writing,
// from this process or another, fails with ERROR_SHARING_VIOLATION until the
// handle is closed, which Windows does on any process exit. Read-only openers
// (diagnostics reading the PID) are still allowed. The handle isn't
// inheritable, so child processes can't keep the lock alive.
func openLocked(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", path, err)
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("failed to open lock file %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}
