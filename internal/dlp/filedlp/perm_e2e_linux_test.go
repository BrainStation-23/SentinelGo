package filedlp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// The cost of blocking (#340): run with SENTINELGO_PERM_COST=1 as root.
// Copies many small clean files to the stick with cp (judged: a copy
// program) and writes as many from a shell (answered at once), with the
// permission group running and without it, and reports wall and agent CPU
// time per open.
func TestPermCost(t *testing.T) {
	if os.Getenv("SENTINELGO_PERM_COST") == "" {
		t.Skip("set SENTINELGO_PERM_COST=1 (root) to measure")
	}
	stick, home, e, _ := startBlockingEnforcer(t, blockBundleE2E)
	eventually(t, "file blocking to start", func() bool { b := e.Health().Blocking; return b != nil && b.State == stateRunning })
	const files = 500
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("f%04d.txt", i)), []byte("lunch at noon"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(script string) (time.Duration, time.Duration) {
		_ = os.RemoveAll(filepath.Join(stick, "out"))
		if err := os.Mkdir(filepath.Join(stick, "out"), 0o777); err != nil {
			t.Fatal(err)
		}
		var before, after syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
		start := time.Now()
		if out, err := exec.Command("/bin/sh", "-c", script, "sh", home, filepath.Join(stick, "out")).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		wall := time.Since(start)
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
		return wall, time.Duration(after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano())
	}
	cpEach := `for f in "$1"/f*; do /bin/cp "$f" "$2"/; done`
	shEach := `for f in "$1"/f*; do printf x > "$2/$(basename "$f")"; done`
	cpOnWall, cpOnCPU := run(cpEach)
	shOnWall, shOnCPU := run(shEach)
	st := e.Health().Blocking
	off := filepath.Join(e.opts.ConfigDir, OffSwitchFile)
	if err := os.WriteFile(off, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "file blocking to stop", func() bool { return e.Health().Blocking.State == blockingOff })
	cpOffWall, _ := run(cpEach)
	shOffWall, _ := run(shEach)
	t.Logf("%d files. cp (judged): %v with blocking, %v without; agent CPU %v (%v per file). shell (allowed at once): %v with, %v without; agent CPU %v. allowed %d, denied %d, timeouts %d, overloaded %d",
		files, cpOnWall.Round(time.Millisecond), cpOffWall.Round(time.Millisecond), cpOnCPU.Round(time.Millisecond), (cpOnCPU / files).Round(time.Microsecond),
		shOnWall.Round(time.Millisecond), shOffWall.Round(time.Millisecond), shOnCPU.Round(time.Millisecond),
		st.Allowed, st.Denied, st.Timeouts, st.Overloaded)
}
