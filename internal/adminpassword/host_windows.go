//go:build windows

package adminpassword

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// netapi32 calls x/sys/windows doesn't wrap. No cgo: plain syscalls.
var (
	modnetapi32        = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserSetInfo = modnetapi32.NewProc("NetUserSetInfo")
	procNetUserEnum    = modnetapi32.NewProc("NetUserEnum")
)

// Network management status codes (lmerr.h, winerror.h).
const (
	nerrSuccess             = 0
	nerrUserNotFound        = 2221
	nerrPasswordTooShort    = 2245 // also returned for complexity failures
	nerrPasswordHistConflic = 2247
	errorPasswordRestrict   = 1325
	errorMoreData           = 234
	filterNormalAccount     = 0x0002
	ufAccountDisable        = 0x0002
	maxPreferredLength      = 0xFFFFFFFF
	ridBuiltinAdmin         = 500
	verNTDomainController   = 2
)

// userInfo2 is USER_INFO_2 (lmaccess.h). Go's natural alignment matches C's.
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

// userInfo20 is USER_INFO_20: the RID is what finds the built-in
// Administrator whatever it was renamed to.
type userInfo20 struct {
	Name     *uint16
	FullName *uint16
	Comment  *uint16
	Flags    uint32
	UserID   uint32
}

// userInfo1003 is USER_INFO_1003: just the new password.
type userInfo1003 struct {
	Password *uint16
}

type windowsHost struct{}

// NewHost returns the platform host.
func NewHost() Host { return windowsHost{} }

func (windowsHost) Unsupported() string {
	// A domain controller has no local accounts: setting "Administrator"
	// there would change the domain's account.
	if windows.RtlGetVersion().ProductType == verNTDomainController {
		return "domain_controller"
	}
	return ""
}

func (windowsHost) ManagedBy() (string, error) {
	return managedByFrom(readHKLMDWORD)
}

func readHKLMDWORD(key, value string) (uint32, bool, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, fmt.Errorf(`HKLM\%s: %w`, key, err)
	}
	defer func() { _ = k.Close() }()
	v, typ, err := k.GetIntegerValue(value)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, true, false, nil
	}
	if err != nil || typ != registry.DWORD {
		// A value of the wrong type is a misconfiguration, not "off".
		return 0, true, false, fmt.Errorf(`HKLM\%s\%s: unreadable DWORD (%v)`, key, value, err)
	}
	return uint32(v), true, true, nil // #nosec G115 - a REG_DWORD holds 32 bits
}

func (h windowsHost) Account(name string) (AccountInfo, error) {
	if name == "" {
		n, err := builtinAdminName()
		if err != nil {
			return AccountInfo{}, err
		}
		name = n
	}
	return accountInfo(name)
}

func (h windowsHost) AccountBySID(sid string) (AccountInfo, error) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("%w: %v", ErrAccountNotFound, err)
	}
	name, domain, _, err := s.LookupAccount("")
	if err != nil {
		return AccountInfo{}, fmt.Errorf("%w: %v", ErrAccountNotFound, err)
	}
	if !isLocalDomain(domain) {
		return AccountInfo{}, fmt.Errorf("%w: %s is not a local account", ErrAccountNotFound, sid)
	}
	return accountInfo(name)
}

// builtinAdminName finds the account with RID 500 in the local SAM.
func builtinAdminName() (string, error) {
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetUserEnum.Call(0, 20, filterNormalAccount,
			uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		if r != nerrSuccess && r != errorMoreData {
			return "", fmt.Errorf("NetUserEnum: %w", windows.Errno(r))
		}
		name := ""
		if buf != nil && read > 0 {
			users := unsafe.Slice((*userInfo20)(unsafe.Pointer(buf)), read)
			for _, u := range users {
				if u.UserID == ridBuiltinAdmin {
					name = windows.UTF16PtrToString(u.Name)
					break
				}
			}
		}
		if buf != nil {
			_ = windows.NetApiBufferFree(buf)
		}
		if name != "" {
			return name, nil
		}
		if r != errorMoreData {
			return "", fmt.Errorf("%w: no account with RID 500", ErrAccountNotFound)
		}
	}
}

// accountInfo reads a local account's state (never its password).
func accountInfo(name string) (AccountInfo, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("%w: %v", ErrAccountNotFound, err)
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, n, 2, &buf); err != nil {
		if errors.Is(err, windows.Errno(nerrUserNotFound)) {
			return AccountInfo{}, fmt.Errorf("%w: %s", ErrAccountNotFound, name)
		}
		return AccountInfo{}, fmt.Errorf("NetUserGetInfo %s: %w", name, err)
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()
	u := (*userInfo2)(unsafe.Pointer(buf))
	now := time.Now()
	info := AccountInfo{
		Name:            windows.UTF16PtrToString(u.Name),
		Enabled:         u.Flags&ufAccountDisable == 0,
		PasswordLastSet: now.Add(-time.Duration(u.PasswordAge) * time.Second).Truncate(time.Second),
	}
	if u.LastLogon != 0 {
		info.LastLogon = time.Unix(int64(u.LastLogon), 0)
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return AccountInfo{}, fmt.Errorf("computer name: %w", err)
	}
	sid, domain, _, err := windows.LookupSID("", computer+`\`+info.Name)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("SID of %s: %w", info.Name, err)
	}
	if !isLocalDomain(domain) {
		return AccountInfo{}, fmt.Errorf("%w: %s resolves to %s, not a local account", ErrAccountNotFound, info.Name, domain)
	}
	info.SID = sid.String()
	info.Builtin = strings.HasSuffix(info.SID, "-500") && strings.HasPrefix(info.SID, "S-1-5-21-")
	return info, nil
}

func isLocalDomain(domain string) bool {
	computer, err := windows.ComputerName()
	return err == nil && strings.EqualFold(domain, computer)
}

func (windowsHost) SetPassword(a AccountInfo, pw []byte) error {
	n, err := windows.UTF16PtrFromString(a.Name)
	if err != nil {
		return err
	}
	// The password is ASCII (Generate), so UTF-16 is one unit per byte;
	// building it by hand keeps it out of any string we can't zero.
	w := make([]uint16, len(pw)+1)
	for i, c := range pw {
		w[i] = uint16(c)
	}
	defer func() {
		for i := range w {
			w[i] = 0
		}
	}()
	info := userInfo1003{Password: &w[0]}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(n)), 1003,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	switch r {
	case nerrSuccess:
		return nil
	case nerrPasswordTooShort, nerrPasswordHistConflic, errorPasswordRestrict:
		return fmt.Errorf("%w (NET %d)", ErrPasswordPolicy, r)
	case nerrUserNotFound:
		return fmt.Errorf("%w: %s", ErrAccountNotFound, a.Name)
	}
	return fmt.Errorf("NetUserSetInfo: %w", windows.Errno(r))
}
