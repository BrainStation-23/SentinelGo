//go:build windows

package winsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedInstallerSID is NT SERVICE\TrustedInstaller. It legitimately holds
// full control over %ProgramFiles% content on a stock system, so finding it in
// a DACL is not a defect.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// dangerousAccess is the set of rights that let a principal alter an object:
// modify its contents, delete it, or -- via WRITE_DAC / WRITE_OWNER -- grant
// itself everything else. For a directory the same bit values mean add-file,
// add-subdirectory and delete-child.
const dangerousAccess = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// Offender is a single ACE granting write-equivalent access to a principal that
// should not have it.
type Offender struct {
	SID      string
	Account  string
	Mask     windows.ACCESS_MASK
	AceFlags uint8
}

// String renders an offender for logs and for the integrity report sent to the
// backend.
func (o Offender) String() string {
	name := o.Account
	if name == "" {
		name = "<unresolved>"
	}
	return fmt.Sprintf("%s (%s) mask=0x%08x flags=0x%02x", name, o.SID, uint32(o.Mask), o.AceFlags)
}

// PathAudit is the result of inspecting one path's security descriptor.
type PathAudit struct {
	Path         string
	Owner        string
	OwnerOK      bool
	Protected    bool
	ReparsePoint bool
	Offenders    []Offender
}

// Secure reports whether the path is safe for a LocalSystem service to execute
// from or to keep secrets in.
//
// All four conditions matter independently:
//
//   - Offenders: an unprivileged principal can write the object.
//   - OwnerOK: an owner holds implicit WRITE_DAC, so a hostile owner can undo
//     any DACL at will -- a clean DACL under the wrong owner proves nothing.
//   - Protected: without a protected DACL the object still inherits from its
//     parent, which is how the original vulnerability arose in the first place.
//   - ReparsePoint: a junction means the name we checked and the bytes that get
//     executed need not be the same object.
func (a *PathAudit) Secure() bool {
	return a != nil &&
		len(a.Offenders) == 0 &&
		a.OwnerOK &&
		a.Protected &&
		!a.ReparsePoint
}

// Reason explains, in one line, why the audit failed. Empty when Secure.
func (a *PathAudit) Reason() string {
	if a.Secure() {
		return ""
	}
	var reasons []string
	if a.ReparsePoint {
		reasons = append(reasons, "path is a reparse point")
	}
	if !a.OwnerOK {
		reasons = append(reasons, fmt.Sprintf("owner %q is not SYSTEM/Administrators/TrustedInstaller", a.Owner))
	}
	if !a.Protected {
		reasons = append(reasons, "DACL is not protected (still inherits from parent)")
	}
	for _, o := range a.Offenders {
		reasons = append(reasons, "writable by "+o.String())
	}
	return strings.Join(reasons, "; ")
}

// AuditPath inspects path's owner and DACL. It is strictly read-only.
func AuditPath(path string) (*PathAudit, error) {
	audit := &PathAudit{Path: path}

	if _, err := os.Lstat(path); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	// Ask Windows directly rather than inferring from Go's mode bits: Go maps
	// only some reparse tags to ModeSymlink, and a directory junction -- the
	// variety an attacker plants to redirect a privileged write -- is among
	// those it can report as an ordinary directory.
	reparse, err := isReparsePoint(path)
	if err != nil {
		return nil, err
	}
	audit.ReparsePoint = reparse

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, fmt.Errorf("read security info for %s: %w", path, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("read owner of %s: %w", path, err)
	}
	if owner != nil {
		audit.Owner = accountName(owner)
		audit.OwnerOK = isPrivilegedSID(owner.String())
	}

	control, _, err := sd.Control()
	if err != nil {
		return nil, fmt.Errorf("read control flags of %s: %w", path, err)
	}
	audit.Protected = control&windows.SE_DACL_PROTECTED != 0

	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("read DACL of %s: %w", path, err)
	}
	offenders, err := daclOffenders(dacl, path)
	if err != nil {
		return nil, err
	}
	audit.Offenders = offenders

	return audit, nil
}

// daclOffenders returns the ACEs in dacl that grant write-equivalent access to
// an unprivileged principal.
func daclOffenders(dacl *windows.ACL, path string) ([]Offender, error) {
	// A nil DACL is not "no access" but "unrestricted access" -- the most
	// permissive state there is, so it must never be read as clean.
	if dacl == nil {
		return []Offender{{
			SID:     "<null DACL>",
			Account: "Everyone (no DACL present)",
			Mask:    windows.GENERIC_ALL,
		}}, nil
	}

	var offenders []Offender
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		// Only allow-ACEs can grant access. Deny-ACEs and audit entries cannot
		// widen it, so they are not offenders.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Mask&dangerousAccess == 0 {
			continue
		}

		// INHERIT_ONLY ACEs are reported too, even though they grant nothing on
		// this object. On a directory they decide what every file created inside
		// it will be granted, which is exactly how the original vulnerability
		// worked: C:\ itself is not writable by standard users, but its
		// inherit-only Authenticated Users:Modify ACE made every child writable.
		// Our own directories carry a protected DACL with no inherited entries,
		// so a surviving inherit-only ACE means inheritance was not severed and
		// the next file written here will be exposed.

		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		if isPrivilegedSID(sid.String()) {
			continue
		}

		offenders = append(offenders, Offender{
			SID:      sid.String(),
			Account:  accountName(sid),
			Mask:     ace.Mask,
			AceFlags: ace.Header.AceFlags,
		})
	}
	return offenders, nil
}

// isReparsePoint reports whether path carries FILE_ATTRIBUTE_REPARSE_POINT,
// covering symlinks, directory junctions and mount points alike.
func isReparsePoint(path string) (bool, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return false, fmt.Errorf("read attributes of %s: %w", path, err)
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

// VerifyPath audits path and returns an error describing the first problem.
func VerifyPath(path string) error {
	audit, err := AuditPath(path)
	if err != nil {
		return err
	}
	if !audit.Secure() {
		return fmt.Errorf("insecure permissions on %s: %s", path, audit.Reason())
	}
	return nil
}

// VerifyFileAndParent audits a file together with the directory containing it.
//
// Auditing the file alone is not enough. A perfectly locked-down binary inside a
// directory that grants FILE_DELETE_CHILD to Users is still replaceable: delete
// the file, write a new one in its place. The directory is part of the file's
// security boundary.
func VerifyFileAndParent(path string) ([]*PathAudit, error) {
	var audits []*PathAudit
	for _, p := range []string{filepath.Dir(path), path} {
		audit, err := AuditPath(p)
		if err != nil {
			return audits, err
		}
		audits = append(audits, audit)
	}
	return audits, nil
}

// isPrivilegedSID reports whether a SID is one that may legitimately hold write
// access to the agent's files.
//
// CREATOR OWNER (S-1-3-0) and OWNER RIGHTS (S-1-3-4) are deliberately absent.
// %ProgramData% carries an inherited "CREATOR OWNER:(OI)(CI)(IO)(F)" ACE, which
// grants full control to whoever creates each child file. Treating it as benign
// is the precise way a relocation to %ProgramData% can look hardened while
// remaining exploitable.
func isPrivilegedSID(sid string) bool {
	switch sid {
	case "S-1-5-18", // NT AUTHORITY\SYSTEM
		"S-1-5-32-544", // BUILTIN\Administrators
		trustedInstallerSID:
		return true
	}
	return false
}

// accountName resolves a SID to DOMAIN\Name, falling back to the SID string.
// Resolution is a convenience for logs and must never gate a security decision,
// which is why every comparison in this file is on the SID itself.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
