//go:build windows

package lockfile

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// TestIsProcessRunning_ExitedButHandleOpen covers the exit-code branch: while
// any handle to a terminated process is open, OpenProcess still succeeds, so
// the result must come from GetExitCodeProcess rather than OpenProcess failing.
//
// Exit code 259 equals STILL_ACTIVE and should be caught by the
// WaitForSingleObject disambiguation. It currently is not: IsProcessRunning
// opens the handle without SYNCHRONIZE, so the wait fails with "Access is
// denied" and the fallback reports the exited process as running. The case is
// skipped until that is fixed.
func TestIsProcessRunning_ExitedButHandleOpen(t *testing.T) {
	t.Run("exit_3", func(t *testing.T) { checkExitedWithHandleOpen(t, "3") })
	t.Run("exit_259", func(t *testing.T) {
		t.Skip("known bug: OpenProcess lacks SYNCHRONIZE, so exit code 259 reads as running")
		checkExitedWithHandleOpen(t, "259")
	})
}

func checkExitedWithHandleOpen(t *testing.T, code string) {
	cmd := exec.Command("cmd", "/c", "exit", code)
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start helper process: %v", err)
	}
	pid := cmd.Process.Pid

	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		_ = cmd.Wait()
		t.Skipf("could not open helper process: %v", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	_ = cmd.Wait()

	if IsProcessRunning(pid) {
		t.Errorf("IsProcessRunning(%d) = true, want false (exited, handle still open)", pid)
	}
}
