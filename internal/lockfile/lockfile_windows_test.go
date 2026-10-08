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
// Exit code 259 equals STILL_ACTIVE and must be caught by the
// WaitForSingleObject disambiguation, which needs SYNCHRONIZE on the handle
// (regression test for #117).
func TestIsProcessRunning_ExitedButHandleOpen(t *testing.T) {
	t.Run("exit_3", func(t *testing.T) { checkExitedWithHandleOpen(t, "3") })
	t.Run("exit_259", func(t *testing.T) { checkExitedWithHandleOpen(t, "259") })
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
