//go:build windows

package artifact

import "sentinelgo/internal/winsec"

// securePath applies a protected DACL to path granting full access only to
// SYSTEM, Administrators, and the current process user. This prevents a
// standard user from replacing a downloaded artifact between hash verification
// and script execution.
func securePath(path string) error {
	return winsec.SecurePath(path)
}
