//go:build windows

package localadmin

import (
	"context"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSLogoffSession            = wtsapi32.NewProc("WTSLogoffSession")
)

const wtsUserName = 5 // WTS_INFO_CLASS WTSUserName

// signOutWindows signs user (a bare account name) out of every session it
// has, active or disconnected, through the Remote Desktop Services API. That
// works the same on every edition and language, unlike parsing quser.
func signOutWindows(_ context.Context, user string) (int, error) {
	var list *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &list, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(list))) // #nosec G103 - memory owned by wtsapi32

	n := 0
	for _, s := range unsafe.Slice(list, count) { // #nosec G103 - count entries returned by WTSEnumerateSessions
		if !strings.EqualFold(sessionUser(s.SessionID), user) {
			continue
		}
		r, _, _ := procWTSLogoffSession.Call(0, uintptr(s.SessionID), 0)
		if r != 0 {
			n++
		}
	}
	return n, nil
}

func sessionUser(session uint32) string {
	var buf *uint16
	var size uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsUserName,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size))) // #nosec G103 - out-parameters
	if r == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf))) // #nosec G103 - memory owned by wtsapi32
	return windows.UTF16PtrToString(buf)
}
