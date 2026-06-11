//go:build !windows

package lockfile

import (
	"os"
	"syscall"
)

// IsProcessRunning reports whether a process with the given PID is currently
// running. On Unix it uses signal 0, which performs the kernel's permission and
// existence checks without delivering an actual signal — it is non-destructive.
func IsProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	return process.Signal(syscall.Signal(0)) == nil
}
