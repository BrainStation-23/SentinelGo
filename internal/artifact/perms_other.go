//go:build !windows

package artifact

// securePath is a no-op on non-Windows platforms. Unix callers enforce access
// through directory and file modes (0700/0600) set during download.
func securePath(_ string) error { return nil }
