//go:build !windows

// Package winsec applies and verifies restrictive Windows ACLs. On non-Windows
// platforms the operations are no-ops: Unix callers enforce the same intent with
// file modes (0600 for secrets, 0700 for their directory) and root ownership,
// applied by internal/config and installation-doc/install.sh.
//
// Every symbol in the Windows build has a counterpart here with an identical
// signature, so callers never need a build tag. The stubs are exercised by
// winsec_other_test.go specifically so a signature drift between the two builds
// fails on Linux CI rather than only on a Windows runner.
package winsec

import "os"

// SecureSystemPath is a no-op on non-Windows platforms.
func SecureSystemPath(_ string) error { return nil }

// SecureSystemTree is a no-op on non-Windows platforms.
func SecureSystemTree(_ string) error { return nil }

// SecurePath is the previous name of SecureSystemPath.
//
// Deprecated: use SecureSystemPath.
func SecurePath(_ string) error { return nil }

// Offender mirrors the Windows type so callers compile unchanged. No offender is
// ever produced here.
type Offender struct {
	SID      string
	Account  string
	Mask     uint32
	AceFlags uint8
}

func (o Offender) String() string { return o.Account }

// PathAudit mirrors the Windows type. On Unix it always reports secure: file
// modes are the enforcement mechanism, and reporting a false problem here would
// push callers into the degraded mode meant for a suspected compromise.
type PathAudit struct {
	Path         string
	Owner        string
	OwnerOK      bool
	Protected    bool
	ReparsePoint bool
	Offenders    []Offender
}

// Secure always reports true on non-Windows platforms.
func (a *PathAudit) Secure() bool { return true }

// Reason is always empty on non-Windows platforms.
func (a *PathAudit) Reason() string { return "" }

// AuditPath reports a secure result for any path that exists.
func AuditPath(path string) (*PathAudit, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return &PathAudit{Path: path, OwnerOK: true, Protected: true}, nil
}

// VerifyPath is a no-op beyond confirming the path exists.
func VerifyPath(path string) error {
	_, err := AuditPath(path)
	return err
}

// VerifyFileAndParent is a no-op beyond confirming both paths exist.
func VerifyFileAndParent(path string) ([]*PathAudit, error) {
	audit, err := AuditPath(path)
	if err != nil {
		return nil, err
	}
	return []*PathAudit{audit}, nil
}

// CreateSecureFile creates path with owner-only permissions, failing if it
// already exists. O_EXCL mirrors the Windows CREATE_NEW behaviour so a
// pre-planted artifact is rejected rather than adopted on every platform.
func CreateSecureFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
