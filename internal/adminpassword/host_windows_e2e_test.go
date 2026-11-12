//go:build windows

package adminpassword

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWindowsHost_SetPasswordE2E creates a throwaway local account, sets a
// generated password on it with SetPassword and logs on with it. It changes
// the device, so it runs only elevated and with SENTINELGO_ADMINPW_E2E=1.
func TestWindowsHost_SetPasswordE2E(t *testing.T) {
	if os.Getenv("SENTINELGO_ADMINPW_E2E") != "1" {
		t.Skip("set SENTINELGO_ADMINPW_E2E=1 and run elevated")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process")
	}
	const user = "sg-e2e-pwtest"
	netapi := windows.NewLazySystemDLL("netapi32.dll")
	add, del := netapi.NewProc("NetUserAdd"), netapi.NewProc("NetUserDel")
	name, _ := windows.UTF16PtrFromString(user)
	first, err := Generate(DefaultLength, 4)
	if err != nil {
		t.Fatal(err)
	}
	firstW, _ := windows.UTF16PtrFromString(string(first))
	// USER_INFO_1: name, password, password_age, priv (USER_PRIV_USER = 1),
	// home_dir, comment, flags (UF_SCRIPT = 1), script_path.
	ui := struct {
		Name, Password    *uint16
		PasswordAge, Priv uint32
		HomeDir, Comment  *uint16
		Flags             uint32
		ScriptPath        *uint16
	}{Name: name, Password: firstW, Priv: 1, Flags: 1}
	if r, _, _ := add.Call(0, 1, uintptr(unsafe.Pointer(&ui)), 0); r != 0 {
		t.Fatalf("NetUserAdd: %d", r)
	}
	t.Cleanup(func() { _, _, _ = del.Call(0, uintptr(unsafe.Pointer(name))) })

	h := NewHost()
	a, err := h.Account(user)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := Generate(DefaultLength, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetPassword(a, pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !logon(t, user, string(pw)) {
		t.Fatal("logon with the new password failed")
	}
	if logon(t, user, string(first)) {
		t.Fatal("the old password still works")
	}
	b, err := h.Account(user)
	if err != nil || b.PasswordLastSet.Before(a.PasswordLastSet) {
		t.Fatalf("password-last-set not updated: %+v, %v", b, err)
	}
}

func logon(t *testing.T, user, pw string) bool {
	t.Helper()
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
	u, _ := windows.UTF16PtrFromString(user)
	d, _ := windows.UTF16PtrFromString(".")
	p, _ := windows.UTF16PtrFromString(pw)
	var tok windows.Token
	// LOGON32_LOGON_NETWORK = 3, LOGON32_PROVIDER_DEFAULT = 0
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)), 3, 0, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return false
	}
	_ = tok.Close()
	return true
}
