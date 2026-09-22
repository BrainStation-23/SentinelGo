//go:build windows

package winsec_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/winsec"
)

// SDDL fragments used to build hostile fixtures.
//
// authUsersInheritOnlyModify reproduces the ACE that caused the vulnerability:
// C:\ carries "Authenticated Users:(OI)(CI)(IO)(M)", an inherit-only Modify
// grant that propagates to every child. 0x1301bf is the Modify access mask.
const (
	authUsersInheritOnlyModify = "(A;OICIIO;0x1301bf;;;AU)"
	usersFullControl           = "(A;OICI;FA;;;BU)"
	creatorOwnerFullControl    = "(A;OICIIO;FA;;;CO)"
	systemAndAdmins            = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

// requireElevatedEnv, when set, turns the elevation skip into a failure.
//
// These are the tests that actually prove the privilege-escalation fix. On a
// developer machine they have to skip, because setting an object's owner to
// BUILTIN\Administrators needs that group active in the token and the filtered
// token of a non-elevated admin does not carry it. But a silent skip in CI would
// leave the build green while nothing was verified -- the failure mode where a
// check that cannot detect the bug is mistaken for a check that passed. CI sets
// this variable so a runner that unexpectedly loses elevation is loud about it.
const requireElevatedEnv = "SENTINELGO_REQUIRE_ELEVATED_TESTS"

func requireElevated(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	if os.Getenv(requireElevatedEnv) != "" {
		t.Fatalf("%s is set but the process is not elevated: the ACL hardening tests "+
			"cannot run, and skipping them would report success without verifying "+
			"anything", requireElevatedEnv)
	}
	t.Skip("requires an elevated token (setting owner to Administrators)")
}

// selfSID returns the current user's SID string, used to keep test fixtures
// accessible to the test process itself.
func selfSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return user.User.Sid.String()
}

// applyDACL sets an explicit DACL from SDDL. protected severs inheritance.
func applyDACL(t *testing.T, path, dacl string, protected bool) {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString("D:" + dacl)
	if err != nil {
		t.Fatalf("parse SDDL %q: %v", dacl, err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("extract DACL: %v", err)
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
}

// newFixtureDir makes a directory whose ACLs the test will rewrite, and arranges
// for it to be removable afterwards even once it has been locked to
// SYSTEM+Administrators.
func newFixtureDir(t *testing.T, name string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	t.Cleanup(func() {
		// Restore inheritance so TempDir's own cleanup can delete the tree.
		grantSelf := "(A;OICI;FA;;;" + selfSID(t) + ")"
		sd, err := windows.SecurityDescriptorFromString("D:" + grantSelf)
		if err != nil {
			return
		}
		acl, _, err := sd.DACL()
		if err != nil {
			return
		}
		_ = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil)
		runtime.KeepAlive(sd)
	})

	return dir
}

func findOffender(audit *winsec.PathAudit, sid string) bool {
	for _, o := range audit.Offenders {
		if o.SID == sid {
			return true
		}
	}
	return false
}

// TestInheritedAuthenticatedUsersModify_IsDetectedAndRemoved is the regression
// test for CyberStation PT-2026-001 finding #1.
//
// It reproduces the vulnerability's exact shape -- a parent carrying an
// inherit-only Authenticated Users:Modify ACE, and a child that inherits it --
// inside a temp directory, so it never touches the real C:\ ACL.
func TestInheritedAuthenticatedUsersModify_IsDetectedAndRemoved(t *testing.T) {
	requireElevated(t)

	parent := newFixtureDir(t, "hostile-parent")
	applyDACL(t, parent, authUsersInheritOnlyModify+systemAndAdmins+
		"(A;OICI;FA;;;"+selfSID(t)+")", true)

	// Created after the ACE is in place, so it inherits it -- exactly how
	// C:\SentinelGo became writable by every standard user.
	child := filepath.Join(parent, "sentinelgo.exe")
	if err := os.WriteFile(child, []byte("binary"), 0o600); err != nil {
		t.Fatalf("create child: %v", err)
	}

	before, err := winsec.AuditPath(child)
	if err != nil {
		t.Fatalf("AuditPath before: %v", err)
	}
	if !findOffender(before, "S-1-5-11") {
		t.Fatalf("fixture did not reproduce the bug: Authenticated Users (S-1-5-11) "+
			"should hold write access via inheritance, got offenders %v (protected=%v)",
			before.Offenders, before.Protected)
	}
	if before.Secure() {
		t.Error("a file writable by Authenticated Users must not audit as secure")
	}

	if err := winsec.SecureSystemPath(child); err != nil {
		t.Fatalf("SecureSystemPath: %v", err)
	}

	after, err := winsec.AuditPath(child)
	if err != nil {
		t.Fatalf("AuditPath after: %v", err)
	}
	if !after.Secure() {
		t.Errorf("path still insecure after hardening: %s", after.Reason())
	}
	if findOffender(after, "S-1-5-11") {
		t.Error("Authenticated Users still holds write access after hardening")
	}
	if !after.Protected {
		t.Error("DACL must be protected, or the parent's ACE returns on the next inherit")
	}
}

// TestSecureSystemPath_SetsOwnerAndSeversInheritance covers the two properties
// that a DACL alone does not provide. An owner keeps implicit WRITE_DAC, so a
// hostile owner can undo any DACL; an unprotected DACL keeps inheriting.
func TestSecureSystemPath_SetsOwnerAndSeversInheritance(t *testing.T) {
	requireElevated(t)

	dir := newFixtureDir(t, "harden-me")
	applyDACL(t, dir, usersFullControl+systemAndAdmins, false)

	if err := winsec.SecureSystemPath(dir); err != nil {
		t.Fatalf("SecureSystemPath: %v", err)
	}

	audit, err := winsec.AuditPath(dir)
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	if !audit.Protected {
		t.Error("DACL is not protected: inheritance from the parent is still live")
	}
	if !audit.OwnerOK {
		t.Errorf("owner = %q, want SYSTEM or Administrators; a non-privileged owner "+
			"keeps implicit WRITE_DAC and can revert this", audit.Owner)
	}
	if len(audit.Offenders) != 0 {
		t.Errorf("unexpected write grants remain: %v", audit.Offenders)
	}
}

// TestAuditPath_FlagsCreatorOwner guards the %ProgramData% relocation trap.
// C:\ProgramData carries an inherited CREATOR OWNER full-control ACE, so every
// child is fully controlled by whoever created it. An allowlist that overlooks
// S-1-3-0 would report such a directory as hardened while it is not.
func TestAuditPath_FlagsCreatorOwner(t *testing.T) {
	requireElevated(t)

	dir := newFixtureDir(t, "creator-owner")
	applyDACL(t, dir, creatorOwnerFullControl+systemAndAdmins, true)

	audit, err := winsec.AuditPath(dir)
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	if !findOffender(audit, "S-1-3-0") {
		t.Errorf("CREATOR OWNER (S-1-3-0) not reported as an offender; offenders = %v",
			audit.Offenders)
	}
}

// TestAuditPath_DetectsUnprotected checks that a default temp directory, which
// inherits from its parent, is not mistaken for hardened.
func TestAuditPath_DetectsUnprotected(t *testing.T) {
	audit, err := winsec.AuditPath(t.TempDir())
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	if audit.Protected {
		t.Error("a freshly created temp directory should still be inheriting")
	}
	if audit.Secure() {
		t.Error("an inheriting directory must not audit as secure")
	}
}

// TestSecureSystemTree_ResetsChildren verifies that hardening the root is not
// enough on its own: a child carrying its own explicit ACE keeps it, so the
// walk has to reset children back to pure inheritance.
func TestSecureSystemTree_ResetsChildren(t *testing.T) {
	requireElevated(t)

	root := newFixtureDir(t, "tree-root")
	child := filepath.Join(root, "nested.txt")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatalf("create child: %v", err)
	}
	applyDACL(t, child, usersFullControl+systemAndAdmins, true)

	if audit, err := winsec.AuditPath(child); err != nil {
		t.Fatalf("AuditPath: %v", err)
	} else if len(audit.Offenders) == 0 {
		t.Fatal("fixture did not reproduce an explicitly-writable child")
	}

	if err := winsec.SecureSystemTree(root); err != nil {
		t.Fatalf("SecureSystemTree: %v", err)
	}

	audit, err := winsec.AuditPath(child)
	if err != nil {
		t.Fatalf("AuditPath after: %v", err)
	}
	if len(audit.Offenders) != 0 {
		t.Errorf("child kept its explicit write grants after the tree walk: %v",
			audit.Offenders)
	}
}

// TestCreateSecureFile_DACLAtCreation is the assertion that the updater TOCTOU
// is gone rather than merely narrowed: the descriptor must already be correct
// while the handle is still open and nothing has been written.
func TestCreateSecureFile_DACLAtCreation(t *testing.T) {
	path := filepath.Join(newFixtureDir(t, "staging"), "sentinelgo.exe.new")

	f, err := winsec.CreateSecureFile(path)
	if err != nil {
		t.Fatalf("CreateSecureFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	audit, err := winsec.AuditPath(path)
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	if len(audit.Offenders) != 0 {
		t.Errorf("staged artifact is writable by %v at creation time", audit.Offenders)
	}
	if !audit.Protected {
		t.Error("staged artifact inherits from its parent at creation time")
	}
}

// TestCreateSecureFile_FailsOnExisting proves CREATE_NEW semantics: a
// pre-planted artifact must be rejected, never adopted and retroactively ACL'd.
func TestCreateSecureFile_FailsOnExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "already-there.new")
	if err := os.WriteFile(path, []byte("planted"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	f, err := winsec.CreateSecureFile(path)
	if err == nil {
		_ = f.Close()
		t.Fatal("CreateSecureFile succeeded on an existing path; a planted artifact " +
			"would be adopted instead of rejected")
	}

	// The content must be untouched: we reject, we do not truncate.
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read back: %v", readErr)
	}
	if string(data) != "planted" {
		t.Errorf("existing file was modified: %q", data)
	}
}

func TestAuditPath_NonExistentPath(t *testing.T) {
	if _, err := winsec.AuditPath(`C:\nonexistent\path\that\does\not\exist.json`); err == nil {
		t.Error("AuditPath on a missing path should return an error, not a secure result")
	}
}

// TestVerifyFileAndParent_AuditsBoth documents why the parent is included: a
// locked-down file inside a directory granting FILE_DELETE_CHILD is still
// replaceable by delete-then-create.
func TestVerifyFileAndParent_AuditsBoth(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	audits, err := winsec.VerifyFileAndParent(file)
	if err != nil {
		t.Fatalf("VerifyFileAndParent: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("got %d audits, want 2 (parent and file)", len(audits))
	}
	if audits[0].Path != dir || audits[1].Path != file {
		t.Errorf("audited %q and %q, want parent %q then file %q",
			audits[0].Path, audits[1].Path, dir, file)
	}
}

// TestDangerousAccessMaskCoversWriteDAC is a guard on the offender mask itself.
// WRITE_DAC is the subtlest entry: a principal holding only WRITE_DAC has no
// direct write access but can grant itself every other right, so omitting it
// would make the audit report a rewritable object as secure.
func TestDangerousAccessMaskCoversWriteDAC(t *testing.T) {
	requireElevated(t)

	dir := newFixtureDir(t, "write-dac")
	// Users get WRITE_DAC (0x00040000) and nothing else.
	applyDACL(t, dir, "(A;OICI;0x00040000;;;BU)"+systemAndAdmins, true)

	audit, err := winsec.AuditPath(dir)
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	if !findOffender(audit, "S-1-5-32-545") {
		t.Errorf("BUILTIN\\Users holding WRITE_DAC was not flagged; offenders = %v",
			audit.Offenders)
	}
}

// Keep the unsafe import meaningful if the file is ever trimmed: the audit code
// relies on ACE layout arithmetic, and this assertion documents the assumption
// that ACCESS_ALLOWED_ACE places its SID immediately after the fixed header.
func TestACELayoutAssumption(t *testing.T) {
	var ace windows.ACCESS_ALLOWED_ACE
	if got, want := unsafe.Offsetof(ace.SidStart), uintptr(8); got != want {
		t.Errorf("ACCESS_ALLOWED_ACE.SidStart offset = %d, want %d; the audit's SID "+
			"arithmetic depends on this layout", got, want)
	}
}
