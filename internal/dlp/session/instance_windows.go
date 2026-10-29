//go:build windows

package session

import (
	"errors"

	"golang.org/x/sys/windows"
)

// AcquireHelperLock makes this the only helper in the user's session (a
// named mutex in the session's Local namespace). ok is false when another
// helper holds it; release frees it.
func AcquireHelperLock() (release func(), ok bool, err error) {
	name, err := windows.UTF16PtrFromString(`Local\SentinelGoDLPSession`)
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(h)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() { _ = windows.CloseHandle(h) }, true, nil
}
