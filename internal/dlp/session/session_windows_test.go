package session

import (
	"os"
	"slices"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
)

// The test's own (interactive) session is listed; session 0 never is.
func TestWinLauncher_Sessions(t *testing.T) {
	l, err := newWinLauncher()
	if err != nil {
		t.Fatalf("newWinLauncher: %v", err)
	}
	ids, err := l.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if slices.Contains(ids, "0") {
		t.Error("session 0 listed")
	}
	var mine uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &mine); err != nil || mine == 0 {
		t.Skip("not running in an interactive session (CI service runner)")
	}
	if !slices.Contains(ids, strconv.FormatUint(uint64(mine), 10)) {
		t.Logf("own session %d not active (%v); disconnected sessions are skipped by design", mine, ids)
	}
}

// Without SYSTEM's SeTcbPrivilege the user token can't be queried: Start
// must fail cleanly (the supervisor then reports start_failed and retries).
func TestWinLauncher_StartWithoutPrivilegeFails(t *testing.T) {
	l, err := newWinLauncher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Start("4294967295"); err == nil {
		t.Error("Start in a non-existent session succeeded")
	}
	if _, err := l.Start("not-a-number"); err == nil {
		t.Error("Start with a bad session id succeeded")
	}
}
