package adminpassword

// Windows LAPS reads its policy from the first of these roots that exists
// (Microsoft's documented precedence): the LAPS CSP, then Group Policy,
// then local configuration. BackupDirectory is 0 (disabled), 1 (Entra ID)
// or 2 (Active Directory).
var windowsLAPSRoots = []string{
	`SOFTWARE\Microsoft\Policies\LAPS`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config`,
}

// legacyLAPSKey is Microsoft's legacy (AdmPwd) LAPS policy; AdmPwdEnabled 1
// turns it on.
const legacyLAPSKey = `SOFTWARE\Policies\Microsoft Services\AdmPwd`

// dwordReader reads an HKLM DWORD. keyExists is false when the key itself
// is missing; found is false when the value is.
type dwordReader func(key, value string) (v uint32, keyExists, found bool, err error)

// managedByFrom decides whether another rotator owns the local admin
// password. The agent stands down whichever account that rotator manages:
// two rotators on one device is a configuration to fix, not to race.
func managedByFrom(read dwordReader) (string, error) {
	for _, root := range windowsLAPSRoots {
		v, exists, found, err := read(root, "BackupDirectory")
		if err != nil {
			return "", err
		}
		if !exists {
			continue
		}
		// The first existing root is the one Windows LAPS uses.
		if found && v != 0 {
			return ManagedByWindowsLAPS, nil
		}
		break
	}
	v, _, found, err := read(legacyLAPSKey, "AdmPwdEnabled")
	if err != nil {
		return "", err
	}
	if found && v == 1 {
		return ManagedByLegacyLAPS, nil
	}
	return "", nil
}
