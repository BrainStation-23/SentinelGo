//go:build windows

// Package winsec applies restrictive Windows ACLs to files and directories that
// hold secrets or executable update artifacts. On non-Windows platforms its
// functions are no-ops (Unix file modes are handled by the caller).
package winsec

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// SecurePath applies a protected DACL to path granting full access to SYSTEM,
// the built-in Administrators group, and the account running this process only.
// Other standard users are denied access. Used for the cleartext config file
// (secrets) and for update artifacts (the staged binary and restart script),
// which run as SYSTEM and must not be tamperable by a non-privileged user during
// the update window.
func SecurePath(path string) error {
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if sid, err := currentUserSID(); err == nil && sid != "" {
		sddl += fmt.Sprintf("(A;OICI;FA;;;%s)", sid)
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}
