package filedlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
)

// blockBundleE2E enforces a block policy on the stick (not audit-only).
var blockBundleE2E = strings.NewReplacer(`"action": "monitor"`, `"action": "block"`,
	`"channels": {"file.removable": true}}`, `"channels": {"file.removable": true}, "audit_only": false}`).Replace(enforcerBundle)

func startBlockingEnforcer(t *testing.T, bundle string) (stick, home string, e *linuxEnforcer, sink *recordingSink) {
	t.Helper()
	stick = fakeStick(t, "serve")
	home = t.TempDir()
	sink = &recordingSink{}
	e = New(Options{Sink: sink, Exe: testExe(t), ConfigDir: t.TempDir()}).(*linuxEnforcer)
	e.Apply(context.Background(), compile(t, bundle))
	t.Cleanup(e.Stop)
	if h := e.Health(); h == nil || h.State != stateRunning {
		t.Skipf("fanotify not available here: %+v", h)
	}
	return stick, home, e, sink
}

func cp(src, dst string) (string, error) {
	out, err := exec.Command("/bin/cp", src, dst).CombinedOutput()
	return string(out), err
}

// End to end as root on a real kernel: cp of a file with a secret to the
// stick is refused before anything is written; a clean file copies; another
// program writing the same content is left to the after-write path.
func TestEnforcer_BlocksCopyEndToEnd(t *testing.T) {
	stick, home, e, sink := startBlockingEnforcer(t, blockBundleE2E)
	eventually(t, "file blocking to start", func() bool {
		b := e.Health().Blocking
		return b != nil && b.State == stateRunning
	})
	secret := filepath.Join(home, "plan.txt")
	clean := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, []byte("lunch at noon"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := cp(secret, filepath.Join(stick, "plan.txt"))
	if err == nil || !strings.Contains(out, "Operation not permitted") {
		t.Fatalf("secret copied: %v %s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(stick, "plan.txt")); strings.Contains(string(b), "TOPSECRET") {
		t.Fatal("content reached the stick")
	}
	eventually(t, "the blocked event", func() bool {
		for _, ev := range sink.events() {
			if ev.Action == events.ActionBlocked {
				return true
			}
		}
		return false
	})
	var blocked events.Event
	for _, ev := range sink.events() {
		if ev.Action == events.ActionBlocked {
			blocked = ev
		}
	}
	if blocked.Correlation == nil || blocked.Correlation.Method != MethodOpenFile || blocked.Process == nil || !strings.HasSuffix(blocked.Process.Path, "cp") {
		t.Fatalf("blocked event %+v correlation %+v", blocked, blocked.Correlation)
	}

	if out, err := cp(clean, filepath.Join(stick, "notes.txt")); err != nil {
		t.Fatalf("clean file refused: %v %s", err, out)
	}

	// Not a copy program: allowed at open, judged after the write.
	if out, err := exec.Command("/bin/sh", "-c", `printf 'the TOPSECRET plan' > "$1"`, "sh", filepath.Join(stick, "shell.txt")).CombinedOutput(); err != nil {
		t.Fatalf("shell write refused: %v %s", err, out)
	}
	if st := e.Health().Blocking; st.Denied != 1 || st.Pending != 0 {
		t.Errorf("blocking stats %+v", st)
	}
}

// Audit-only never starts the permission group: the copy goes through.
func TestEnforcer_AuditOnlyNeverBlocks(t *testing.T) {
	audit := strings.Replace(blockBundleE2E, `"audit_only": false`, `"audit_only": true`, 1)
	stick, home, e, _ := startBlockingEnforcer(t, audit)
	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * mountPoll) // let the mount loop run
	if out, err := cp(secret, filepath.Join(stick, "plan.txt")); err != nil {
		t.Fatalf("audit-only blocked: %v %s", err, out)
	}
	if b := e.Health().Blocking; b == nil || b.State != blockingOff {
		t.Errorf("blocking %+v", b)
	}
}

// The emergency switch turns blocking off within a mount poll.
func TestEnforcer_OffSwitchStopsBlocking(t *testing.T) {
	stick, home, e, _ := startBlockingEnforcer(t, blockBundleE2E)
	eventually(t, "file blocking to start", func() bool { b := e.Health().Blocking; return b != nil && b.State == stateRunning })
	if err := os.WriteFile(filepath.Join(e.opts.ConfigDir, OffSwitchFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "file blocking to stop", func() bool { return e.Health().Blocking.State == blockingOff })
	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := cp(secret, filepath.Join(stick, "plan.txt")); err != nil {
		t.Fatalf("blocked with the switch on: %v %s", err, out)
	}
}

// Stopping the hook while an open is held answers it (allow): nothing stays
// frozen.
func TestEnforcer_StopReleasesHeldOpens(t *testing.T) {
	stick, home, e, _ := startBlockingEnforcer(t, blockBundleE2E)
	eventually(t, "file blocking to start", func() bool { b := e.Health().Blocking; return b != nil && b.State == stateRunning })
	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := cp(secret, filepath.Join(stick, "x.txt")); done <- err }()
	e.Stop()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("cp still held after Stop")
	}
}

// A stalled event loop trips the watchdog: the group is closed (the kernel
// allows what was held), blocking stays off and says why.
func TestEnforcer_WatchdogFailsOpen(t *testing.T) {
	stick, home, e, _ := startBlockingEnforcer(t, blockBundleE2E)
	eventually(t, "file blocking to start", func() bool { b := e.Health().Blocking; return b != nil && b.State == stateRunning })
	old := permStallAfter
	permStallAfter = time.Nanosecond // every check now looks like a stall
	t.Cleanup(func() { permStallAfter = old })
	eventually(t, "the watchdog", func() bool { return e.Health().Blocking.State == blockingWatchdog })
	permStallAfter = old
	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * mountPoll) // it must not come back by itself
	if out, err := cp(secret, filepath.Join(stick, "plan.txt")); err != nil {
		t.Fatalf("blocked after the watchdog: %v %s", err, out)
	}
	if e.Health().Blocking.State != blockingWatchdog {
		t.Fatal("blocking restarted without a restart of the hook")
	}
}
