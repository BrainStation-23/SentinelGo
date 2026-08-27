package osinfo

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// These tests cover the cancellation debt recorded as item 4 in
// docs/telemetry/06-existing-code-observations.md: Collect took no context, so
// the scheduler bounded it by abandoning a goroutine — which stopped the
// waiting but not the work, leaking a goroutine and a process tree per tick.

// TestCollectContextRespectsAnAlreadyCancelledContext pins the cheapest and
// most important case: an expired deadline must cost nothing at all, not a full
// inventory cycle whose result is then discarded.
func TestCollectContextRespectsAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	info, err := CollectContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled context must surface as an error, not a silent full collection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if info != nil {
		t.Error("a cancelled collection must return nil rather than a partially " +
			"filled SystemInfo: an incomplete inventory is fingerprinted and " +
			"uploaded as the machine's real state, reporting hardware as missing")
	}
	if elapsed > 5*time.Second {
		t.Errorf("a pre-cancelled collection took %v; the cancellation check is "+
			"not being reached before the expensive collectors", elapsed)
	}
}

// TestCollectContextReturnsPromptlyOnDeadline bounds how long a cancelled cycle
// can overrun.
//
// The bound is generous on purpose. Only the security collector cancels its own
// subprocesses; the rest are gated between collectors, so one already-running
// collector finishes, itself capped by the 30-second timeout inside
// shared.RunCommand. What must NOT happen is the whole cycle running to
// completion, which on Windows is 20–60 seconds of PowerShell.
func TestCollectContextReturnsPromptlyOnDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real OS collectors")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := CollectContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Skip("collection finished inside the deadline on this host; nothing to assert")
	}
	if elapsed > 45*time.Second {
		t.Errorf("cancelled collection took %v: the deadline is not stopping the "+
			"cycle, only the caller's wait", elapsed)
	}
}

// TestCollectPreservesExistingBehaviour pins that the context-free entry point
// still works exactly as before for the debug CLI, which has no context.
func TestCollectPreservesExistingBehaviour(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real OS collectors")
	}

	info := Collect()
	if info == nil {
		t.Skip("host.Info() unavailable in this environment")
	}
	if info.Hostname == "" {
		t.Error("Collect returned a SystemInfo with no hostname; the successful " +
			"path changed")
	}
	if info.Timestamp.IsZero() {
		t.Error("Collect returned a SystemInfo with no timestamp")
	}
}

// TestCollectContextSucceedsWithAmpleTime is the other half: adding
// cancellation must not have made a normal collection fail.
func TestCollectContextSucceedsWithAmpleTime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real OS collectors")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	info, err := CollectContext(ctx)
	if err != nil {
		t.Fatalf("CollectContext with a 3-minute budget failed: %v", err)
	}
	if info == nil {
		t.Skip("host.Info() unavailable in this environment")
	}
	if info.Hostname == "" {
		t.Error("collection succeeded but produced no hostname")
	}
}

// TestSubprocessIsKilledOnCancellation is the direct proof of the property the
// whole change exists for: a cancelled context must terminate the child
// process, not merely stop waiting for it.
//
// It exercises shared.RunCommandContext — the helper every migrated collector
// now uses — rather than a collector, because a collector's real subprocess
// cannot be made to hang on demand.
func TestSubprocessIsKilledOnCancellation(t *testing.T) {
	sleeper, args := sleepCommand(3600)
	if sleeper == "" {
		t.Skip("no long-sleeping command available on this platform")
	}
	if _, err := exec.LookPath(sleeper); err != nil {
		t.Skipf("%s not on PATH", sleeper)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := shared.RunCommandContext(ctx, sleeper, args...)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a command outliving its context must return an error")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("the child process ran for %v after its context expired; "+
			"cancellation is not reaching the subprocess", elapsed)
	}
}

// sleepCommand returns a command that blocks for the given number of seconds.
func sleepCommand(seconds int) (string, []string) {
	if runtime.GOOS == "windows" {
		// timeout.exe needs a console; ping to a non-routable address with a
		// long wait is the portable way to block a Windows child process.
		return "ping", []string{"-n", "3600", "127.0.0.1"}
	}
	return "sleep", []string{strconv.Itoa(seconds)}
}
