//go:build windows

package enforce

import "golang.org/x/sys/windows"

// defaultKill terminates pid via OpenProcess(PROCESS_TERMINATE) +
// TerminateProcess — the standard, immediate (not graceful) Windows process
// kill primitive. There is no equivalent of SIGKILL-vs-SIGTERM choice on
// Windows worth exposing here: TerminateProcess is already the forceful
// option, matching the containment framing this package is built around
// (see the package doc comment).
func defaultKill(pid int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return windows.TerminateProcess(handle, 1)
}
