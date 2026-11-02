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

// taintBundleE2E: a block policy, after-write action record, taint on, and
// unscannable files allowed, so only a correlation produces an event.
var taintBundleE2E = strings.NewReplacer(`"action": "monitor"`, `"action": "block"`,
	`"channels": {"file.removable": true}}`,
	`"channels": {"file.removable": true}, "audit_only": false, "copy_correlation": {"process_taint": true}}`).Replace(enforcerBundle)

// startTaintEnforcer runs the enforcer on a fake stick with taint watching
// home (a temp dir); it waits until the open mark is in place.
func startTaintEnforcer(t *testing.T) (stick, home string, e *linuxEnforcer, sink *recordingSink) {
	t.Helper()
	stick = fakeStick(t, "serve")
	home = t.TempDir()
	prev := taintRoot
	taintRoot = home
	t.Cleanup(func() { taintRoot = prev })
	sink = &recordingSink{}
	e = New(Options{Sink: sink, Exe: testExe(t), ConfigDir: t.TempDir()}).(*linuxEnforcer)
	e.Apply(context.Background(), compile(t, taintBundleE2E))
	t.Cleanup(e.Stop)
	if h := e.Health(); h == nil || h.State != stateRunning {
		t.Skipf("fanotify not available here: %+v", h)
	}
	eventually(t, "the open mark", func() bool { tk := e.taint.Load(); return tk != nil && tk.marked })
	return stick, home, e, sink
}

// End to end as root: one process reads a file with a secret, then writes an
// unreadable blob to the stick; the event comes from the file it read.
func TestEnforcer_TaintEndToEnd(t *testing.T) {
	stick, home, e, sink := startTaintEnforcer(t)
	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	blob := `printf '\001\002\003\000\377binary' > "$2"`
	// Same shell process: reads with the read builtin, writes with printf.
	cmd := exec.Command("/bin/sh", "-c", `read -r x < "$1"; `+blob, "sh", secret, filepath.Join(stick, "out.bin"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	eventually(t, "the correlated event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.Correlation == nil || ev.Correlation.Method != "taint" || ev.Scan.VerdictSource != "correlation" ||
		ev.Correlation.SourceName == nil || *ev.Correlation.SourceName != "plan.txt" || ev.Findings[0].Detector != "custom.keywords" {
		t.Fatalf("event %+v correlation %+v", ev, ev.Correlation)
	}
	if ev.Action != events.ActionMonitored {
		t.Errorf("action %q (on_close_violation is record)", ev.Action)
	}
	// Another process writing the same blob without reading anything: no event.
	if out, err := exec.Command("/bin/sh", "-c", blob, "sh", "", filepath.Join(stick, "other.bin")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	time.Sleep(time.Second)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events: an untainted write was correlated", n)
	}
	if cc := e.CopyCorrelation(); cc[MethodProcessTaint] != "supported" {
		t.Errorf("capability %v", cc)
	}
}

// The cost of watching opens: run with SENTINELGO_TAINT_COST=1 as root.
// Reports the workload's wall time and the agent's CPU time with the open
// mark in place and without it, and opens lost to the queue.
func TestTaintCost(t *testing.T) {
	if os.Getenv("SENTINELGO_TAINT_COST") == "" {
		t.Skip("set SENTINELGO_TAINT_COST=1 (root) to measure")
	}
	_, home, e, _ := startTaintEnforcer(t)
	const files, rounds = 2000, 50
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("f%04d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	workload := fmt.Sprintf(`i=0; while [ $i -lt %d ]; do cat "$1"/f* > /dev/null; i=$((i+1)); done`, rounds)
	measure := func() (time.Duration, time.Duration) {
		var before, after syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
		start := time.Now()
		if out, err := exec.Command("/bin/sh", "-c", workload, "sh", home).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		wall := time.Since(start)
		time.Sleep(time.Second) // let the reader drain
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
		cpu := time.Duration(after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano())
		return wall, cpu
	}
	onWall, onCPU := measure()
	tk := e.taint.Load()
	_ = markOpens(tk.fan, false, taintRoot)
	tk.marked = false
	prev := taintRoot
	taintRoot = "/nonexistent-for-the-measurement" // keep the loop from marking again
	defer func() { taintRoot = prev }()
	offWall, offCPU := measure()
	h := e.Health()
	t.Logf("%d opens: workload %v with the open mark, %v without; agent CPU %v with, %v without; open events lost to overflow: %d; processes tracked: %d",
		files*rounds, onWall.Round(time.Millisecond), offWall.Round(time.Millisecond), onCPU.Round(time.Millisecond), offCPU.Round(time.Millisecond),
		h.TaintOverflows, h.TaintProcesses)
}
