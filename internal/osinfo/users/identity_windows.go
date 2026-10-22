package users

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/osinfo/shared"
)

// identityScript reads, in one PowerShell start, the members of the local
// Administrators group (found by its well-known SID, so a localized or
// renamed group works), the machine's account-domain SID, the console user
// and domain membership (#223). Get-LocalGroupMember throws when the group
// holds a SID it can't resolve, which is common on Entra-joined devices;
// ADSI lists the members then, with their paths and SIDs.
var identityScript = strings.Join([]string{
	`$r = @{}`,
	`$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')`,
	`try { $r.admins = @(Get-LocalGroupMember -SID $sid -ErrorAction Stop | ForEach-Object { @{ name = [string]$_.Name; sid = [string]$_.SID.Value; source = [string]$_.PrincipalSource; class = [string]$_.ObjectClass } }) } catch { try { $n = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]; $g = [ADSI]('WinNT://./' + $n + ',group'); $r.admin_paths = @($g.psbase.Invoke('Members') | ForEach-Object { $t = $_.GetType(); $s = ''; try { $s = (New-Object System.Security.Principal.SecurityIdentifier($t.InvokeMember('objectSid', 'GetProperty', $null, $_, $null), 0)).Value } catch {}; @{ path = [string]$t.InvokeMember('ADsPath', 'GetProperty', $null, $_, $null); sid = $s; class = [string]$t.InvokeMember('Class', 'GetProperty', $null, $_, $null) } }) } catch {} }`,
	`try { $r.machine_sid = [string](Get-LocalUser -ErrorAction Stop | Select-Object -First 1).SID.AccountDomainSid.Value } catch {}`,
	`try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop; $r.console_user = [string]$cs.UserName; $r.part_of_domain = [bool]$cs.PartOfDomain; $r.domain = [string]$cs.Domain } catch {}`,
	`ConvertTo-Json -InputObject $r -Compress -Depth 4`,
}, "; ")

func getIdentity() shared.UserIdentity {
	var id shared.UserIdentity
	probe, probeOK := windowsIdentityProbe{}, false
	if out, err := shared.RunPowerShell(identityScript); err == nil {
		probe, probeOK = parseWindowsIdentityProbe(out)
	}
	if probeOK {
		id.AdminMembers = probe.adminMembers()
	}

	if sessions, err := windowsSessions(); err == nil {
		id.SignedInUsers = sessions
	} else if probeOK {
		id.SignedInUsers = probe.consoleSession()
	}

	id.LastSignedInUser = windowsLastSignedInUser()

	if out, err := shared.RunCommand("dsregcmd", "/status"); err == nil {
		if j, ok := parseDsregcmd(out); ok {
			id.Join = j
		}
	}
	if id.Join == nil && probeOK {
		id.Join = probe.windowsJoinFallback()
	}
	return id
}

// windowsLastSignedInUser reads the account LogonUI shows as the last one
// to sign in interactively.
func windowsLastSignedInUser() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	for _, name := range []string{"LastLoggedOnSAMUser", "LastLoggedOnUser"} {
		if v, _, err := k.GetStringValue(name); err == nil && strings.TrimSpace(v) != "" {
			return windowsLastUser(v)
		}
	}
	return ""
}

var (
	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
)

// WTS_INFO_CLASS values.
const (
	wtsClientProtocolType = 16
	wtsSessionInfo        = 24
)

// WTS_CONNECTSTATE_CLASS values.
const (
	wtsActive       = 0
	wtsDisconnected = 4
)

// wtsInfo is WTSINFOW.
type wtsInfo struct {
	State                   uint32
	SessionID               uint32
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
	WinStationName          [32]uint16
	Domain                  [17]uint16
	UserName                [21]uint16
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	LogonTime               int64
	CurrentTime             int64
}

// windowsSessions lists the signed-in users' sessions (active or
// disconnected) from the Remote Desktop Services API, which works the same
// on every edition and language, unlike parsing quser.
func windowsSessions() ([]shared.SignedInUser, error) {
	var list *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &list, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(list))) // #nosec G103 - memory owned by wtsapi32

	users := []shared.SignedInUser{}
	for _, s := range unsafe.Slice(list, count) { // #nosec G103 - count entries returned by WTSEnumerateSessions
		info, ok := querySessionInfo(s.SessionID)
		if !ok || (info.State != wtsActive && info.State != wtsDisconnected) {
			continue
		}
		user := windows.UTF16ToString(info.UserName[:])
		if user == "" {
			continue
		}
		u := shared.SignedInUser{
			Username: user,
			Domain:   windows.UTF16ToString(info.Domain[:]),
			Session:  wtsSessionKind(querySessionProtocol(s.SessionID)),
			State:    "active",
		}
		if info.State == wtsDisconnected {
			u.State = "disconnected"
		}
		if info.LogonTime > 0 {
			ft := windows.Filetime{LowDateTime: uint32(info.LogonTime), HighDateTime: uint32(info.LogonTime >> 32)} // #nosec G115 - FILETIME halves
			u.Since = shared.ISOTime(time.Unix(0, ft.Nanoseconds()))
		}
		users = append(users, u)
	}
	return users, nil
}

// querySessionBuffer calls WTSQuerySessionInformationW and returns the
// buffer it allocated, which the caller frees with WTSFreeMemory.
func querySessionBuffer(session uint32, class uintptr) (buf *byte, size uint32, ok bool) {
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), class,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size))) // #nosec G103 - out-parameters
	return buf, size, r != 0 && buf != nil
}

func freeSessionBuffer(buf *byte) {
	windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf))) // #nosec G103 - memory owned by wtsapi32
}

func querySessionInfo(session uint32) (wtsInfo, bool) {
	buf, size, ok := querySessionBuffer(session, wtsSessionInfo)
	if !ok {
		return wtsInfo{}, false
	}
	defer freeSessionBuffer(buf)
	if uintptr(size) < unsafe.Sizeof(wtsInfo{}) {
		return wtsInfo{}, false
	}
	return *(*wtsInfo)(unsafe.Pointer(buf)), true // #nosec G103 - WTSINFOW returned by the API
}

// querySessionProtocol returns WTSClientProtocolType: 0 console, 1 ICA,
// 2 RDP. 0 when it can't be read.
func querySessionProtocol(session uint32) uint16 {
	buf, size, ok := querySessionBuffer(session, wtsClientProtocolType)
	if !ok {
		return 0
	}
	defer freeSessionBuffer(buf)
	if size < 2 {
		return 0
	}
	return *(*uint16)(unsafe.Pointer(buf)) // #nosec G103 - USHORT returned by the API
}
