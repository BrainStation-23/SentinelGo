//go:build windows

package winsec

import "golang.org/x/sys/windows"

// RunningAsSystem reports whether the current process token is LocalSystem.
//
// Self-defense uses this to decide how to react to a path it could not secure.
// As LocalSystem we hold every privilege that could possibly be needed, so a
// failure there means something is actively preventing the change rather than
// that we simply lacked rights -- a materially different situation from the same
// failure in an unprivileged CLI invocation.
func RunningAsSystem() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
