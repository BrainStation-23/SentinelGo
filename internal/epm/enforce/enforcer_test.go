package enforce

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/epm/procmon"
)

// fakeMonitor is a hand-rolled procmon.Monitor: internal (non-_test-suffixed)
// test files in package enforce are compiled as part of the package for Go's
// cycle-detection purposes, and enforce already imports procmon, so a real
// platform Monitor cannot be constructed portably here anyway — this fake
// gives full, deterministic control over the event stream instead.
type fakeMonitor struct {
	ch chan procmon.ProcessEvent
}

func newFakeMonitor() *fakeMonitor {
	return &fakeMonitor{ch: make(chan procmon.ProcessEvent, 64)}
}

func (m *fakeMonitor) Start() error                        { return nil }
func (m *fakeMonitor) Events() <-chan procmon.ProcessEvent { return m.ch }
func (m *fakeMonitor) Dropped() uint64                     { return 0 }
func (m *fakeMonitor) Stop()                               { close(m.ch) }
func (m *fakeMonitor) push(ev procmon.ProcessEvent)        { m.ch <- ev }

var _ procmon.Monitor = (*fakeMonitor)(nil)

// fakeKiller records every pid it was asked to kill.
type fakeKiller struct {
	mu      sync.Mutex
	killed  []int
	failPID int // if set, kill(failPID) returns an error instead of succeeding
}

func (k *fakeKiller) kill(pid int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failPID != 0 && pid == k.failPID {
		return errors.New("simulated kill failure")
	}
	k.killed = append(k.killed, pid)
	return nil
}

func (k *fakeKiller) killedPIDs() []int {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]int, len(k.killed))
	copy(out, k.killed)
	return out
}

func startEvent(pid, ppid int, imagePath string) procmon.ProcessEvent {
	have := procmon.HavePID | procmon.HaveParentPID
	if imagePath != "" {
		have |= procmon.HaveImagePath
	}
	return procmon.ProcessEvent{Kind: procmon.EventStart, PID: pid, ParentPID: ppid, ImagePath: imagePath, Have: have}
}

func exitEvent(pid int) procmon.ProcessEvent {
	return procmon.ProcessEvent{Kind: procmon.EventExit, PID: pid, Have: procmon.HavePID}
}

// waitForKills polls killedPIDs until want are seen or the deadline expires.
func waitForKills(t *testing.T, k *fakeKiller, want int) []int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := k.killedPIDs(); len(got) >= want {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d kill(s), got %v", want, k.killedPIDs())
	return nil
}

func denyRootDecision(ruleID string) epm.Decision {
	return epm.Decision{RuleID: ruleID, Outcome: epm.Outcome{Constraints: epm.Constraints{ChildProcess: epm.ChildDeny}}}
}

func allowlistRootDecision(ruleID string, allowed ...string) epm.Decision {
	return epm.Decision{RuleID: ruleID, Outcome: epm.Outcome{Constraints: epm.Constraints{ChildProcess: epm.ChildAllowlist, ChildAllowed: allowed}}}
}

func TestTracker_TrackRoot_IgnoresInheritAndObserve(t *testing.T) {
	tr := NewTracker()
	tr.TrackRoot(1, epm.Decision{Outcome: epm.Outcome{Constraints: epm.Constraints{ChildProcess: epm.ChildInherit}}})
	tr.TrackRoot(2, epm.Decision{Outcome: epm.Outcome{Constraints: epm.Constraints{ChildProcess: epm.ChildObserve}}})
	if got := tr.rootCount(); got != 0 {
		t.Errorf("rootCount() = %d, want 0 (Inherit/Observe must not be tracked)", got)
	}
}

func TestTracker_TrackRoot_RecordsDenyAndAllowlist(t *testing.T) {
	tr := NewTracker()
	tr.TrackRoot(10, denyRootDecision("rule-a"))
	tr.TrackRoot(20, allowlistRootDecision("rule-b", "/bin/*"))
	if got := tr.rootCount(); got != 2 {
		t.Errorf("rootCount() = %d, want 2", got)
	}
}

func newTestEnforcer(t *testing.T, tracker *Tracker, monitor procmon.Monitor, killer *fakeKiller, opts ...Option) *Enforcer {
	t.Helper()
	allOpts := append([]Option{WithKillFunc(killer.kill)}, opts...)
	return NewEnforcer(tracker, monitor, 999999 /* selfPID, unlikely to collide */, nil, allOpts...)
}

func TestEnforcer_KillsChildViolatingDenyPolicy(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/evil"))

	got := waitForKills(t, killer, 1)
	if got[0] != 200 {
		t.Errorf("killed %v, want [200]", got)
	}
}

func TestEnforcer_AllowlistPermitsMatchingChild(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, allowlistRootDecision("only-bin", "/bin/*"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/allowed-tool"))
	mon.push(startEvent(201, 100, "/opt/not-allowed"))

	got := waitForKills(t, killer, 1)
	if len(got) != 1 || got[0] != 201 {
		t.Errorf("killed %v, want exactly [201] (the non-matching child)", got)
	}
}

func TestEnforcer_GrandchildInheritsRootPolicy(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/mid")) // child of root — itself killed
	waitForKills(t, killer, 1)
	mon.push(startEvent(300, 200, "/bin/grandchild")) // grandchild of root via 200's ancestry

	got := waitForKills(t, killer, 2)
	if len(got) != 2 || got[1] != 300 {
		t.Errorf("killed %v, want [200 300]", got)
	}
}

func TestEnforcer_UnrelatedProcessNeverKilled(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(500, 1, "/usr/bin/unrelated")) // parent is PID 1, not the tracked root

	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 0 {
		t.Errorf("killed %v, want none", got)
	}
}

func TestEnforcer_MissingImagePathNeverKilled(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "")) // no image path resolved

	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 0 {
		t.Errorf("killed %v, want none (unverifiable data must never be killed)", got)
	}
}

func TestEnforcer_NeverKillListProtectsSelfPID(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	// selfPID intentionally matches the child's PID this time.
	e := NewEnforcer(tracker, mon, 200, nil, WithKillFunc(killer.kill))

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/self"))

	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 0 {
		t.Errorf("killed %v, want none (self-PID must never be killed)", got)
	}
}

func TestEnforcer_NeverKillListProtectsCriticalImageNames(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/sbin/init"))

	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 0 {
		t.Errorf("killed %v, want none (init must never be killed)", got)
	}
}

func TestEnforcer_ExitForgetsRootAndAncestry(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(exitEvent(100)) // root exits before any child is observed
	time.Sleep(20 * time.Millisecond)

	mon.push(startEvent(200, 100, "/bin/late-child"))

	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 0 {
		t.Errorf("killed %v, want none (root was forgotten after exit)", got)
	}
	if got := tracker.rootCount(); got != 0 {
		t.Errorf("rootCount() = %d, want 0 after root exit", got)
	}
}

func TestEnforcer_KillRateLimiterTripsAndStaysTripped(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{}
	e := newTestEnforcer(t, tracker, mon, killer, WithMaxKillsPerMinute(2))

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/one"))
	mon.push(startEvent(201, 100, "/bin/two"))
	waitForKills(t, killer, 2)

	mon.push(startEvent(202, 100, "/bin/three")) // third kill this minute — must be blocked
	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 2 {
		t.Errorf("killed %v, want exactly 2 (rate limiter should have blocked the third)", got)
	}
	if !e.limiter.isTripped() {
		t.Error("limiter.isTripped() = false, want true")
	}

	// Even a brand new violation must stay blocked — the trip is permanent
	// for the run, not a sliding-window reset.
	mon.push(startEvent(203, 100, "/bin/four"))
	time.Sleep(50 * time.Millisecond)
	if got := killer.killedPIDs(); len(got) != 2 {
		t.Errorf("killed %v after trip, want still exactly 2", got)
	}
}

func TestEnforcer_KillFailureIsLoggedNotFatal(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackRoot(100, denyRootDecision("deny-all-children"))

	mon := newFakeMonitor()
	killer := &fakeKiller{failPID: 200}
	e := newTestEnforcer(t, tracker, mon, killer)

	e.Start(context.Background())
	defer e.Stop()

	mon.push(startEvent(200, 100, "/bin/fails-to-die")) // kill fails
	time.Sleep(30 * time.Millisecond)
	mon.push(startEvent(201, 100, "/bin/succeeds"))

	got := waitForKills(t, killer, 1)
	if len(got) != 1 || got[0] != 201 {
		t.Errorf("killed %v, want exactly [201] (200's failure must not stop the loop)", got)
	}
}

func TestKillRateLimiter_WindowSlides(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := newKillRateLimiter(2, clock)

	if !l.allow() {
		t.Fatal("1st allow() = false, want true")
	}
	if !l.allow() {
		t.Fatal("2nd allow() = false, want true")
	}
	if l.allow() {
		t.Fatal("3rd allow() = true, want false (limit reached)")
	}
	if !l.isTripped() {
		t.Error("isTripped() = false after exceeding the limit, want true")
	}

	// Advancing time must not un-trip it — the trip is a one-way gate.
	now = now.Add(2 * time.Minute)
	if l.allow() {
		t.Error("allow() = true after the window would have cleared, want false (trip is permanent)")
	}
}

func TestNeverKillList_ProtectsWellKnownPIDs(t *testing.T) {
	n := newNeverKillList(999, nil)
	for _, pid := range []int{0, 1, 4} {
		if !n.protects(pid, "/some/path") {
			t.Errorf("protects(%d, ...) = false, want true", pid)
		}
	}
}

func TestNeverKillList_ProtectsSelfAncestry(t *testing.T) {
	n := newNeverKillList(999, []int{100, 200})
	if !n.protects(100, "") {
		t.Error("protects(100 [ancestor]) = false, want true")
	}
	if n.protects(300, "/bin/unrelated") {
		t.Error("protects(300 [unrelated]) = true, want false")
	}
}

func TestNeverKillList_ProtectsByImageNameCaseInsensitive(t *testing.T) {
	n := newNeverKillList(999, nil)
	cases := []string{
		`C:\Windows\System32\lsass.exe`,
		`C:\Windows\System32\LSASS.EXE`,
		"/usr/lib/systemd/systemd",
		"/sbin/init",
		"/sbin/launchd",
	}
	for _, path := range cases {
		if !n.protects(12345, path) {
			t.Errorf("protects(_, %q) = false, want true", path)
		}
	}
}

func TestImagePathAllowed(t *testing.T) {
	cases := []struct {
		name      string
		imagePath string
		patterns  []string
		want      bool
	}{
		{"exact glob match", "/bin/tool", []string{"/bin/*"}, true},
		{"no patterns configured", "/bin/tool", nil, false},
		{"windows path normalized against forward-slash pattern", `C:\Tools\tool.exe`, []string{"C:/Tools/*"}, true},
		{"no match", "/opt/other", []string{"/bin/*"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := imagePathAllowed(tc.imagePath, tc.patterns); got != tc.want {
				t.Errorf("imagePathAllowed(%q, %v) = %v, want %v", tc.imagePath, tc.patterns, got, tc.want)
			}
		})
	}
}
