package mdmenroll

import (
	"context"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modMDMRegistration = windows.NewLazySystemDLL("MDMRegistration.dll")
	procRegister       = modMDMRegistration.NewProc("RegisterDeviceWithManagement")
	procUnregister     = modMDMRegistration.NewProc("UnregisterDeviceWithManagement")
)

// noConsoleSession is what WTSGetActiveConsoleSessionId returns when no
// session is attached to the console.
const noConsoleSession = 0xFFFFFFFF

// ConsoleSession returns the session attached to the PC's console.
func ConsoleSession() (Session, bool) {
	id := windows.WTSGetActiveConsoleSessionId()
	if id == noConsoleSession || id == 0 {
		return Session{}, false
	}
	s := strconv.FormatUint(uint64(id), 10)
	return Session{ID: s, User: "the user of session " + s}, true
}

// RenewADE: Automated Device Enrollment is Apple's.
var RenewADE func(ctx context.Context) error

// OpenProfileForUser is nil: Windows has no configuration profiles to present.
var OpenProfileForUser func(name string, data []byte) error

// OpenURLForUser runs in the session helper, as the user: ShellExecute hands
// the ms-device-enrollment: link to Settings.
var OpenURLForUser = func(u string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// RegisterWindows enrolls the device in MDM silently with
// RegisterDeviceWithManagement. It needs an elevated caller: the service
// (SYSTEM). The token is passed to Windows only, never logged.
func RegisterWindows(upn, discoveryURL, accessToken string) error {
	if err := procRegister.Find(); err != nil {
		return fmt.Errorf("MDM registration isn't available on this Windows: %w", err)
	}
	args := make([]uintptr, 3)
	for i, s := range []string{upn, discoveryURL, accessToken} {
		p, err := windows.UTF16PtrFromString(s)
		if err != nil {
			return err
		}
		args[i] = uintptr(unsafe.Pointer(p)) // #nosec G103 -- Win32 string argument
	}
	hr, _, _ := procRegister.Call(args...)
	return hresult("RegisterDeviceWithManagement", hr)
}

// UnregisterWindows removes one MDM enrollment (by its GUID) with
// UnregisterDeviceWithManagement.
func UnregisterWindows(enrollmentID string) error {
	if !validEnrollmentID(enrollmentID) {
		return fmt.Errorf("unexpected enrollment ID %q", enrollmentID)
	}
	if err := procUnregister.Find(); err != nil {
		return fmt.Errorf("MDM registration isn't available on this Windows: %w", err)
	}
	id, err := windows.UTF16PtrFromString(enrollmentID)
	if err != nil {
		return err
	}
	hr, _, _ := procUnregister.Call(uintptr(unsafe.Pointer(id))) // #nosec G103 -- Win32 string argument
	return hresult("UnregisterDeviceWithManagement", hr)
}

// hresult turns a failed HRESULT into an error with Windows' message.
func hresult(fn string, hr uintptr) error {
	if hr == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08X (%v)", fn, uint32(hr), syscall.Errno(hr)) // #nosec G115 -- an HRESULT is 32 bits; the upper half of the register is unused
}
