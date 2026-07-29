//go:build linux || darwin

package enforce

import "syscall"

// defaultKill sends SIGKILL — immediate, un-catchable termination, matching
// the containment framing this package is built around (see the package
// doc comment): a violating child is not asked to exit gracefully, it is
// terminated outright.
func defaultKill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
