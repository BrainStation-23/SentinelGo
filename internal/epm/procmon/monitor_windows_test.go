//go:build windows

package procmon

import (
	"strings"
	"testing"
)

func TestNew_ReturnsNonNilMonitor(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestWindowsMonitor_StartStop is a live smoke test: it actually calls
// EvtSubscribe against the real Security channel and tears it down again.
// It does not assert anything about delivered events (triggering a real
// 4688 deterministically from a test would need to launch a process with
// audit policy already enabled, which is an environment precondition this
// test cannot assume) — only that Start/Stop do not error or hang. Skipped
// under -short since it touches a live OS subsystem, and skipped (not
// failed) when EvtSubscribe reports access denied: reading the Security
// channel needs the process to run elevated (the real agent runs as
// SYSTEM/Administrator; a plain dev/CI shell does not), the same
// "environment precondition, not a code defect" gate the plan applies to
// Linux's root-only netlink/proc-connector tests.
func TestWindowsMonitor_StartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("live EvtSubscribe session; skipped under -short")
	}
	m := New()
	if err := m.Start(); err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			t.Skip("EvtSubscribe on Security channel requires an elevated process; skipping in this unprivileged test shell")
		}
		t.Fatalf("Start() error = %v", err)
	}
	m.Stop()
}
