//go:build windows

package notify

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procSHQueryUserNotificationState = windows.NewLazySystemDLL("shell32.dll").NewProc("SHQueryUserNotificationState")

func regDWORD(root registry.Key, path, name string) *uint32 {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return nil
	}
	u := uint32(v) // #nosec G115 -- a REG_DWORD
	return &u
}

// Readiness reads this user's notification settings (HKCU: the helper runs
// as the user) and whether the shell accepts notifications right now.
func Readiness() (state, detail string) {
	s := winSettings{
		PolicyNoToast: regDWORD(registry.CURRENT_USER, `Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`, "NoToastApplicationNotification"),
		ToastEnabled:  regDWORD(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\PushNotifications`, "ToastEnabled"),
		AppEnabled:    regDWORD(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\`+sentinelGoAUMID, "Enabled"),
	}
	if s.PolicyNoToast == nil {
		s.PolicyNoToast = regDWORD(registry.LOCAL_MACHINE, `Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`, "NoToastApplicationNotification")
	}
	var q uint32
	if r, _, _ := procSHQueryUserNotificationState.Call(uintptr(unsafe.Pointer(&q))); r == 0 { // #nosec G103 -- out-parameter; S_OK is 0
		s.QUNS = q
	}
	return winReadiness(s)
}
