package mdm

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/osinfo/shared"
)

var (
	modMDMRegistration     = windows.NewLazySystemDLL("MDMRegistration.dll")
	procIsDeviceRegistered = modMDMRegistration.NewProc("IsDeviceRegisteredWithManagement")
	procIsRegistrationOK   = modMDMRegistration.NewProc("IsManagementRegistrationAllowed")
)

const regRead = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY

// readWinFacts is the registry and API reading; a var for tests.
var readWinFacts = func() winFacts {
	f := winFacts{
		editionID:        regString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "EditionID"),
		installationType: regString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "InstallationType"),
		omadmDeviceID:    regString(`SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID`, "DeviceClientId"),
		smbiosUUID:       regString(`SYSTEM\HardwareConfig`, "LastConfig"),
		enrollments:      readEnrollments(),
	}
	f.allowed = registrationAllowed()
	f.registered = deviceRegistered()
	return f
}

func collect(ourHost string) *shared.MDMInfo {
	return buildWindowsInfo(readWinFacts(), ourHost, time.Now())
}

func regString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, regRead)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// readEnrollments lists HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}. Most
// entries aren't MDM enrollments; buildWindowsInfo filters them.
func readEnrollments() []winEnrollment {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, regRead)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []winEnrollment
	for _, name := range names {
		k, err := registry.OpenKey(root, name, regRead)
		if err != nil {
			continue
		}
		e := winEnrollment{id: name}
		e.providerID, _, _ = k.GetStringValue("ProviderID")
		e.discoveryURL, _, _ = k.GetStringValue("DiscoveryServiceFullURL")
		e.upn, _, _ = k.GetStringValue("UPN")
		e.typ, _, _ = k.GetIntegerValue("EnrollmentType")
		e.state, _, _ = k.GetIntegerValue("EnrollmentState")
		_ = k.Close()
		out = append(out, e)
	}
	return out
}

// registrationAllowed calls IsManagementRegistrationAllowed: false when local
// policy blocks MDM enrollment. nil when the API isn't available.
func registrationAllowed() *bool {
	if procIsRegistrationOK.Find() != nil {
		return nil
	}
	var ok int32
	hr, _, _ := procIsRegistrationOK.Call(uintptr(unsafe.Pointer(&ok))) // #nosec G103 -- Win32 out parameter
	if hr != 0 {
		return nil
	}
	return boolPtr(ok != 0)
}

// deviceRegistered calls IsDeviceRegisteredWithManagement. nil when the API
// isn't available (e.g. Windows Server).
func deviceRegistered() *bool {
	if procIsDeviceRegistered.Find() != nil {
		return nil
	}
	var registered int32
	upn := make([]uint16, 256)
	hr, _, _ := procIsDeviceRegistered.Call(
		uintptr(unsafe.Pointer(&registered)), // #nosec G103 -- Win32 out parameter
		uintptr(len(upn)),
		uintptr(unsafe.Pointer(&upn[0])), // #nosec G103 -- Win32 out buffer
	)
	if hr != 0 {
		return nil
	}
	return boolPtr(registered != 0)
}
