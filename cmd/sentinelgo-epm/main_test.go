package main

import "testing"

// TestRun_MissingAppPath pins the one path through run() reachable without a
// live agent transport: -app is unconditionally required outside of
// -session/-install-session/-uninstall-session, so this never calls
// epm.RequestElevation (which would otherwise dial a real pipe/socket that
// does not exist in a test environment).
func TestRun_MissingAppPath(t *testing.T) {
	if got := run(nil); got != 2 {
		t.Errorf("run(nil) = %d, want 2", got)
	}
}

func TestRun_ScriptWithoutAppIsAlsoRejected(t *testing.T) {
	// -script without -app must fail the same way: -app is unconditionally
	// required, so this is never accepted as "-script implies -app".
	if got := run([]string{"-script", "/tmp/install.msi"}); got != 2 {
		t.Errorf("run(-script only) = %d, want 2", got)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	if got := run([]string{"-nonexistent-flag"}); got != 2 {
		t.Errorf("run(-nonexistent-flag) = %d, want 2", got)
	}
}

// TestRun_InstallAndUninstallSession exercise the real per-platform
// autostart Install/Uninstall via os.Executable() — safe to run for real
// (unlike -session's transport dial or the one-shot elevation path) since
// Install/Uninstall only ever touch this user's own autostart location
// (registry Run key / ~/.config/autostart / ~/Library/LaunchAgents), which
// is exactly what a real "-install-session" invocation would do; the test
// cleans up afterward via Uninstall.
func TestRun_InstallAndUninstallSession(t *testing.T) {
	if got := run([]string{"-install-session"}); got != 0 {
		t.Fatalf("run(-install-session) = %d, want 0", got)
	}
	if got := run([]string{"-uninstall-session"}); got != 0 {
		t.Errorf("run(-uninstall-session) = %d, want 0", got)
	}
}

func TestRun_UninstallSessionWithoutInstallIsHarmless(t *testing.T) {
	// Uninstalling something never installed must not be treated as an
	// error — matches every other "delete if present" operation in this
	// codebase (e.g. store.EPMStore.PruneAuditLog on an empty table).
	if got := run([]string{"-uninstall-session"}); got != 0 {
		t.Errorf("run(-uninstall-session) with nothing installed = %d, want 0", got)
	}
}

func TestNoopPrompter_Available(t *testing.T) {
	if (noopPrompter{}).Available() {
		t.Error("noopPrompter.Available() = true, want false")
	}
}

func TestNoopPrompter_MethodsError(t *testing.T) {
	p := noopPrompter{}
	if _, err := p.Confirm("t", "m"); err == nil {
		t.Error("Confirm() error = nil, want an error")
	}
	if _, _, err := p.Justify("t", "m"); err == nil {
		t.Error("Justify() error = nil, want an error")
	}
	if err := p.Notify("t", "m"); err == nil {
		t.Error("Notify() error = nil, want an error")
	}
}
