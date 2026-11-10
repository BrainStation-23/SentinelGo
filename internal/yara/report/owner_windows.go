package report

import "golang.org/x/sys/windows"

// ownerID returns the file's owner SID. Reading the security descriptor
// doesn't open the file's data.
func ownerID(path string) (string, bool) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", false
	}
	sid, _, err := sd.Owner()
	if err != nil || sid == nil {
		return "", false
	}
	return sid.String(), true
}

// ownerName resolves a SID to DOMAIN\name.
func ownerName(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
