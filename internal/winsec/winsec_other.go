//go:build !windows

package winsec

// SecurePath is a no-op on non-Windows platforms; Unix callers enforce access
// with file modes (0600/0700) instead of ACLs.
func SecurePath(_ string) error { return nil }
