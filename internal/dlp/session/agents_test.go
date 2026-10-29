package session

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/ipc"
)

type fakeAgents struct {
	mu          sync.Mutex
	users       []string
	installs    int
	uninstalled bool
	starts      []string // "user" or "user!restart"
	stops       []string
	startErr    map[string]error // Start fails for these users
}

func (f *fakeAgents) Install() error { f.mu.Lock(); f.installs++; f.mu.Unlock(); return nil }
func (f *fakeAgents) Uninstall() error {
	f.mu.Lock()
	f.uninstalled = true
	f.mu.Unlock()
	return nil
}
func (f *fakeAgents) Users() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.users), nil
}
func (f *fakeAgents) Start(u string, restart bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if restart {
		u += "!restart"
	}
	f.starts = append(f.starts, u)
	return f.startErr[strings.TrimSuffix(u, "!restart")]
}
func (f *fakeAgents) Stop(u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, u)
	return nil
}

func TestAgentSupervisor(t *testing.T) {
	fa := &fakeAgents{users: []string{"alice"}}
	hub := NewHub("unused", &recordingSink{})
	s := newAgentSupervisor(hub, fa)

	s.reconcile()
	connect(hub, "alice", "alice")
	s.reconcile()
	// First start after the service starts replaces an old helper (it may
	// run the binary from before a self-update); a connected one is left
	// alone.
	if !slices.Equal(fa.starts, []string{"alice!restart"}) || fa.installs != 1 {
		t.Fatalf("starts = %v installs = %d", fa.starts, fa.installs)
	}

	fa.users = []string{"alice", "bob"}
	s.reconcile()
	if !slices.Equal(fa.starts, []string{"alice!restart", "bob"}) {
		t.Errorf("starts = %v, want bob started (no restart)", fa.starts)
	}
	// bob's helper hasn't connected: the next pass starts it again (a no-op
	// for a running helper; it revives one launchd loaded but doesn't run).
	s.reconcile()
	if !slices.Equal(fa.starts, []string{"alice!restart", "bob", "bob"}) {
		t.Errorf("starts = %v, want bob started again while not connected", fa.starts)
	}

	fa.users = []string{"alice"} // bob logged out, then back in
	s.reconcile()
	fa.users = []string{"alice", "bob"}
	s.reconcile()
	if got := fa.starts[len(fa.starts)-1]; got != "bob" {
		t.Errorf("bob's new login not started: %v", fa.starts)
	}

	s.Stop()
	if !fa.uninstalled || !slices.Equal(fa.stops, []string{"alice", "bob"}) {
		t.Errorf("Stop: uninstalled=%v stops=%v", fa.uninstalled, fa.stops)
	}
}

// connect registers a connected helper for user with the hub, as serve does.
func connect(h *Hub, user, sessionID string) *helper {
	hp := &helper{id: ipc.Identity{User: user, SessionID: sessionID}, state: "running", caps: map[string]string{"clipboard": "supported"}}
	h.mu.Lock()
	h.helpers[hp] = struct{}{}
	h.mu.Unlock()
	return hp
}

// A failed restart doesn't spend the restart: the next pass replaces the
// helper again instead of only checking that the job is loaded (#299).
func TestAgentSupervisor_FailedRestartRetried(t *testing.T) {
	fa := &fakeAgents{users: []string{"501"}, startErr: map[string]error{"501": errors.New("launchctl kickstart -k gui/501: signal: killed")}}
	s := newAgentSupervisor(NewHub("unused", &recordingSink{}), fa)
	s.reconcile()
	s.reconcile()
	fa.startErr = nil
	s.reconcile()
	s.reconcile()
	want := []string{"501!restart", "501!restart", "501!restart", "501"}
	if !slices.Equal(fa.starts, want) {
		t.Errorf("starts = %v, want %v", fa.starts, want)
	}
}

// Sessions reports users whose helper isn't connected, and why (#299).
func TestAgentSupervisor_Sessions(t *testing.T) {
	fa := &fakeAgents{users: []string{"501", "502", "503"}, startErr: map[string]error{"502": errors.New("launchctl bootstrap gui/502: exit status 5")}}
	hub := NewHub("unused", &recordingSink{})
	s := newAgentSupervisor(hub, fa)
	s.label = func(uid string) (string, string) {
		if name, ok := map[string]string{"501": "alice", "502": "bob", "503": "carol"}[uid]; ok {
			return name, uid
		}
		return uid, uid
	}

	s.reconcile()
	connect(hub, "alice", "501")
	hub.setLastError("503", "helper disconnected before hello")

	got := s.Sessions()
	want := []Info{
		{User: "alice", State: "running", SessionID: "501", Capabilities: map[string]string{"clipboard": "supported"}},
		{User: "bob", State: stateFailed, SessionID: "502", LastError: "launchctl bootstrap gui/502: exit status 5"},
		{User: "carol", State: stateRestarting, SessionID: "503", LastError: "helper disconnected before hello"},
	}
	if !equalInfos(got, want) {
		t.Fatalf("Sessions =\n%+v\nwant\n%+v", got, want)
	}

	// A later start (not the first pass) reports "starting"; a user who
	// logs out is dropped.
	fa.startErr = nil
	hub.setLastError("503", "")
	fa.users = []string{"501", "503"}
	s.reconcile()
	fa.users = []string{"501", "503", "504"}
	s.reconcile()
	got = s.Sessions()
	want = []Info{
		{User: "504", State: stateStarting, SessionID: "504"},
		{User: "alice", State: "running", SessionID: "501", Capabilities: map[string]string{"clipboard": "supported"}},
		{User: "carol", State: stateStarting, SessionID: "503"},
	}
	if !equalInfos(got, want) {
		t.Errorf("Sessions =\n%+v\nwant\n%+v", got, want)
	}
}

// Install and Users failures are reported as one entry, and cleared once
// they work.
func TestAgentSupervisor_SessionsSetupError(t *testing.T) {
	fa := &failingInstall{fakeAgents: fakeAgents{users: []string{"alice"}}, fail: true}
	s := newAgentSupervisor(NewHub("unused", &recordingSink{}), fa)
	s.reconcile()
	got := s.Sessions()
	if len(got) != 1 || got[0].State != stateFailed || got[0].LastError != "install session helper definition: read-only filesystem" {
		t.Fatalf("Sessions = %+v", got)
	}
	fa.fail = false
	s.reconcile()
	got = s.Sessions()
	if len(got) != 1 || got[0].User != "alice" || got[0].LastError != "" {
		t.Errorf("Sessions after install worked = %+v", got)
	}
}

func equalInfos(a, b []Info) bool {
	return slices.EqualFunc(a, b, func(x, y Info) bool {
		return x.User == y.User && x.State == y.State && x.SessionID == y.SessionID && x.LastError == y.LastError &&
			len(x.Capabilities) == len(y.Capabilities) && x.Capabilities["clipboard"] == y.Capabilities["clipboard"]
	})
}

// Apply starts the reconcile loop once; Stop ends it and uninstalls.
func TestAgentSupervisor_ApplyLoop(t *testing.T) {
	fa := &fakeAgents{users: []string{"alice"}}
	s := newAgentSupervisor(NewHub(testAddress(t), &recordingSink{}), fa)
	s.poll = 10 * time.Millisecond
	p := compiled(t, "v1", true)
	s.Apply(context.Background(), p)
	s.Apply(context.Background(), p)
	deadline := time.Now().Add(5 * time.Second)
	for {
		fa.mu.Lock()
		n := len(fa.starts)
		fa.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("loop didn't start the helper")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	if !fa.uninstalled {
		t.Error("Stop didn't uninstall")
	}
}

// Install failures are retried by the next reconcile.
func TestAgentSupervisor_InstallFailureRetried(t *testing.T) {
	fa := &failingInstall{fakeAgents: fakeAgents{users: []string{"alice"}}, fail: true}
	s := newAgentSupervisor(NewHub("unused", &recordingSink{}), fa)
	s.reconcile()
	if len(fa.starts) != 0 {
		t.Fatal("started without an installed definition")
	}
	fa.fail = false
	s.reconcile()
	if len(fa.starts) != 1 {
		t.Errorf("starts = %v after install succeeded", fa.starts)
	}
}

type failingInstall struct {
	fakeAgents
	fail bool
}

func (f *failingInstall) Install() error {
	if f.fail {
		return errors.New("read-only filesystem")
	}
	return f.fakeAgents.Install()
}
