package session

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeProc is a helper process the test ends or kills.
type fakeProc struct {
	done   chan struct{}
	once   sync.Once
	killed bool
	mu     sync.Mutex
}

func newFakeProc() *fakeProc    { return &fakeProc{done: make(chan struct{})} }
func (p *fakeProc) Wait() error { <-p.done; return nil }
func (p *fakeProc) exit()       { p.once.Do(func() { close(p.done) }) }
func (p *fakeProc) Kill() error {
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	p.exit()
	return nil
}

func (p *fakeProc) wasKilled() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.killed }

// fakeLauncher serves a settable session list and records launches.
type fakeLauncher struct {
	mu       sync.Mutex
	sessions []string
	started  map[string][]*fakeProc
	fail     bool
}

func (l *fakeLauncher) Sessions() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.sessions), nil
}

func (l *fakeLauncher) Start(s string) (Process, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return nil, errors.New("no token")
	}
	p := newFakeProc()
	l.started[s] = append(l.started[s], p)
	return p, nil
}

func (l *fakeLauncher) set(s ...string) { l.mu.Lock(); l.sessions = s; l.mu.Unlock() }
func (l *fakeLauncher) procs(s string) []*fakeProc {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.started[s])
}

func newTestSupervisor(l *fakeLauncher) *launchSupervisor {
	s := newLaunchSupervisor(NewHub("unused", &recordingSink{}), l)
	s.backoff = func(int) time.Duration { return 10 * time.Second }
	s.stopWait = 100 * time.Millisecond
	return s
}

func TestLauncher_OneHelperPerSession(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	s := newTestSupervisor(l)
	now := time.Unix(1_700_000_000, 0)

	l.set("1", "2")
	s.reconcile(now)
	s.reconcile(now.Add(time.Second))
	if len(l.procs("1")) != 1 || len(l.procs("2")) != 1 {
		t.Fatalf("launches: s1=%d s2=%d, want exactly one each", len(l.procs("1")), len(l.procs("2")))
	}

	// Session 2 logs off: its helper is stopped.
	l.set("1")
	s.reconcile(now.Add(2 * time.Second))
	if !l.procs("2")[0].wasKilled() {
		t.Error("helper of the ended session not stopped")
	}
}

func TestLauncher_RestartsWithBackoff(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	s := newTestSupervisor(l)
	now := time.Unix(1_700_000_000, 0)
	l.set("1")
	s.reconcile(now)

	l.procs("1")[0].exit() // the user killed it
	waitExited(t, s, "1")
	s.reconcile(now.Add(time.Second))
	if got := len(l.procs("1")); got != 1 {
		t.Fatalf("restarted before backoff: %d launches", got)
	}
	if !slices.ContainsFunc(s.Sessions(), func(i Info) bool { return i.State == stateRestarting }) {
		t.Errorf("Sessions() = %+v, want the restart visible", s.Sessions())
	}

	s.reconcile(now.Add(12 * time.Second))
	if got := len(l.procs("1")); got != 2 {
		t.Fatalf("launches after backoff = %d, want 2", got)
	}
	if slices.ContainsFunc(s.Sessions(), func(i Info) bool { return i.State == stateRestarting }) {
		t.Error("still reported restarting after a successful restart")
	}
}

func TestLauncher_StartFailureReportedAndRetried(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}, fail: true}
	s := newTestSupervisor(l)
	now := time.Unix(1_700_000_000, 0)
	l.set("3")
	s.reconcile(now)
	if !slices.ContainsFunc(s.Sessions(), func(i Info) bool { return i.State == stateFailed }) {
		t.Errorf("Sessions() = %+v, want start_failed", s.Sessions())
	}
	l.mu.Lock()
	l.fail = false
	l.mu.Unlock()
	s.reconcile(now.Add(11 * time.Second))
	if len(l.procs("3")) != 1 {
		t.Error("start not retried after backoff")
	}
}

func TestLauncher_StopKillsStragglers(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	s := newTestSupervisor(l)
	l.set("1")
	s.reconcile(time.Now())
	s.Stop() // the fake helper never exits by itself
	if !l.procs("1")[0].wasKilled() {
		t.Error("helper still running after Stop")
	}
}

// waitExited waits until the supervisor's watcher has seen the exit.
func waitExited(t *testing.T, s *launchSupervisor, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		ch := s.helpers[id].exited
		s.mu.Unlock()
		select {
		case <-ch:
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("exit not observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Apply starts the reconcile loop once; Sessions lists restarting helpers.
func TestLauncher_ApplyRunsLoop(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	l.set("7")
	s := newTestSupervisor(l)
	s.poll = 10 * time.Millisecond
	s.Hub = NewHub(testAddress(t), &recordingSink{})
	p := compiled(t, "v1", true)
	s.Apply(context.Background(), p)
	s.Apply(context.Background(), p) // second Apply: no second loop
	deadline := time.Now().Add(5 * time.Second)
	for len(l.procs("7")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("helper not started by the loop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	if got := len(l.procs("7")); got != 1 {
		t.Errorf("launches = %d, want 1", got)
	}
}

func TestManualSupervisor(t *testing.T) {
	m := &manualSupervisor{Hub: NewHub(testAddress(t), &recordingSink{})}
	m.Apply(context.Background(), compiled(t, "v1", true))
	m.Apply(context.Background(), compiled(t, "v2", true))
	m.Stop()
}

// A started helper that hasn't connected yet is reported as starting.
func TestLauncher_StartingHelperVisible(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	s := newTestSupervisor(l)
	l.set("4")
	s.reconcile(time.Now())
	got := s.Sessions()
	if len(got) != 1 || got[0].State != stateStarting || got[0].SessionID != "4" {
		t.Errorf("Sessions() = %+v, want session 4 starting", got)
	}
}

// A helper that exits without connecting is reported restarting, with the
// reason its last connection failed; the reason goes when the session ends.
func TestLauncher_RestartingHelperShowsLastError(t *testing.T) {
	l := &fakeLauncher{started: map[string][]*fakeProc{}}
	s := newTestSupervisor(l)
	now := time.Unix(1_700_000_000, 0)
	l.set("5")
	s.reconcile(now)
	s.setLastError("5", "helper disconnected before hello")

	l.procs("5")[0].exit() // gave up on an untrusted endpoint
	waitExited(t, s, "5")
	s.reconcile(now.Add(time.Second))
	got := s.Sessions()
	if len(got) != 1 || got[0].State != stateRestarting || got[0].LastError != "helper disconnected before hello" {
		t.Errorf("Sessions() = %+v, want session 5 restarting with its last error", got)
	}

	l.set()
	s.reconcile(now.Add(2 * time.Second))
	if s.lastError("5") != "" {
		t.Error("last error kept after the session ended")
	}
}
