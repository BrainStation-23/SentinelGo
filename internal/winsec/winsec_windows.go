//go:build windows

// Package winsec applies and verifies restrictive Windows ACLs on the files and
// directories that hold the agent's secrets and its executable update artifacts.
// On non-Windows platforms its functions are no-ops or trivially-secure stubs;
// Unix callers enforce access with file modes instead.
package winsec

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protected DACLs granting full control to LocalSystem (SY) and the built-in
// Administrators group (BA), and to nobody else.
//
// "D:P" makes the DACL protected, i.e. inheritance from the parent is severed.
// That is the entire point on Windows: a directory created under C:\ inherits
// the drive root's "Authenticated Users:(OI)(CI)(IO)(M)" ACE and becomes
// writable by every standard user. Severing inheritance is what stops that, and
// it is why callers must never "reset" one of these paths back to inheriting.
//
// The directory form carries (OI)(CI) so new children inherit the same grant.
// The file form omits them: inheritance flags on a leaf object mean nothing.
const (
	systemDirDACL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	systemFileDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// Privilege names, spelled out because x/sys/windows does not export them.
// These are stable Win32 identifiers, not localised display names.
const (
	seTakeOwnershipName = "SeTakeOwnershipPrivilege"
	seRestoreName       = "SeRestorePrivilege"
)

// Deliberately NOT in these DACLs:
//
//   - The calling user's own SID. An earlier version appended it, which looks
//     harmless and is not. BUILTIN\Administrators grants access only to an
//     *elevated* token; the filtered token an admin normally runs with does not
//     carry that SID. An explicit per-user ACE has no such condition, so adding
//     one lets any medium-integrity process running as that admin -- a browser,
//     a document macro -- overwrite the agent binary with no UAC prompt. It also
//     pins one operator's identity into the DACL permanently, surviving their
//     demotion or departure. When the service itself runs, the process token is
//     LocalSystem, so the ACE was redundant even on its own terms.
//
//   - BUILTIN\Users read access. These paths hold agent_secret and both tokens
//     in cleartext; read is exactly the capability being denied.
//
//   - The NT SERVICE\SentinelGo service SID. The service runs as LocalSystem, so
//     SY already covers it. Adding it would mean resolving an account that does
//     not exist until the service is registered, i.e. a new failure branch for a
//     benefit nothing currently needs.

// SecureSystemPath applies the protected DACL to path and sets its owner to
// BUILTIN\Administrators.
//
// Owner matters as much as the DACL. An object's owner holds implicit
// READ_CONTROL and WRITE_DAC no matter what the DACL says, so if a standard user
// created the directory first -- which the C:\ root ACL permits -- a protected
// DACL that excludes them is decorative: they can simply rewrite it. Owner and
// DACL are set in a single call so there is no window in which a hostile owner
// could re-open the object between the two.
func SecureSystemPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return applyProtectedSD(path, info.IsDir())
}

// SecureSystemTree applies the protected DACL to root and then strips explicit
// ACEs from everything beneath it, so the whole subtree resolves to the same
// grant by inheritance.
//
// Applying a protected DACL to a directory does not disturb children that carry
// their own explicit ACEs, so a subtree hardened only at the root can still
// contain a writable file. This is the equivalent of "icacls <root>\* /reset /T".
func SecureSystemTree(root string) error {
	if err := SecureSystemPath(root); err != nil {
		return err
	}

	var firstErr error
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			// An unreadable child is worth reporting but must not abort the
			// walk: the remaining entries still need resetting.
			if firstErr == nil {
				firstErr = fmt.Errorf("walk %s: %w", path, walkErr)
			}
			return nil
		}
		if path == root {
			return nil
		}
		if err := resetToInherited(path); err != nil && firstErr == nil {
			firstErr = err
		}
		return nil
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// SecurePath is the previous name of SecureSystemPath.
//
// Deprecated: use SecureSystemPath. Retained so existing call sites keep
// compiling during the migration.
func SecurePath(path string) error { return SecureSystemPath(path) }

// applyProtectedSD sets owner and protected DACL on path in one operation.
func applyProtectedSD(path string, isDir bool) error {
	sddl := systemFileDACL
	if isDir {
		sddl = systemDirDACL
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}

	// Taking ownership from a hostile pre-created directory needs the privilege
	// explicitly enabled; it is held but disabled by default. Best-effort: when
	// we already have WRITE_OWNER (the normal case, since Administrators is in
	// our token) none of this is required, and if it is required and
	// unavailable, SetNamedSecurityInfo below reports the real failure.
	if restore, err := enablePrivilege(seTakeOwnershipName); err == nil {
		defer restore()
	}
	if restore, err := enablePrivilege(seRestoreName); err == nil {
		defer restore()
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins,
		nil,
		dacl,
		nil,
	)
	// dacl points into sd; keep sd alive until the syscall has consumed it.
	runtime.KeepAlive(sd)
	if err != nil {
		return fmt.Errorf("set security info on %s: %w", path, err)
	}
	return nil
}

// resetToInherited removes any explicit DACL from path and re-enables
// inheritance, so the effective permissions come entirely from the parent.
//
// An empty-but-present DACL combined with UNPROTECTED is what produces "inherit
// everything, grant nothing of your own". Passing a nil DACL would instead mean
// "no DACL at all", which Windows reads as unrestricted access.
func resetToInherited(path string) error {
	emptyACL, err := windows.ACLFromEntries(nil, nil)
	if err != nil {
		return fmt.Errorf("build empty ACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		emptyACL,
		nil,
	); err != nil {
		return fmt.Errorf("reset ACL on %s: %w", path, err)
	}
	return nil
}

// enablePrivilege enables a privilege on the current process token and returns a
// function restoring the previous state.
//
// AdjustTokenPrivileges reports success even when the privilege is not held, so
// the caller must not read a nil error as "the privilege is now active". Callers
// here treat it as best-effort and let the operation that actually needs it
// surface any real failure.
func enablePrivilege(name string) (restore func(), err error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		_ = token.Close()
		return nil, err
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		_ = token.Close()
		return nil, fmt.Errorf("lookup privilege %s: %w", name, err)
	}

	newState := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}

	var previous windows.Tokenprivileges
	var previousLen uint32
	if err := windows.AdjustTokenPrivileges(
		token, false, &newState,
		uint32(unsafe.Sizeof(previous)), &previous, &previousLen,
	); err != nil {
		_ = token.Close()
		return nil, fmt.Errorf("enable privilege %s: %w", name, err)
	}

	return func() {
		if previousLen > 0 {
			_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
		}
		_ = token.Close()
	}, nil
}
