//go:build windows

package lockfile

import "golang.org/x/sys/windows"

// stillActive is the value GetExitCodeProcess reports for a process that has
// not yet terminated (STILL_ACTIVE / STATUS_PENDING).
const stillActive = 259

// waitTimeout is the value WaitForSingleObject returns when the wait expired
// before the object was signaled (WAIT_TIMEOUT, 0x102) — i.e. the process is
// still running.
const waitTimeout = uint32(0x102)

// IsProcessRunning reports whether a process with the given PID is currently
// running, WITHOUT affecting it. It opens a query-only handle and inspects the
// process state; it never terminates the target.
func IsProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Process does not exist, or we lack rights to query it. Treat the
		// common case (no such process) as "not running".
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	if code != stillActive {
		return false
	}

	// Disambiguate the rare case where a terminated process exited with code
	// 259: a still-running process leaves WaitForSingleObject in WAIT_TIMEOUT,
	// whereas a terminated one is already signaled.
	event, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		// Fall back to the exit-code result if the wait could not be performed.
		return true
	}
	return event == waitTimeout
}
