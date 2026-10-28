package session

import (
	"slices"
	"sync"
	"testing"
)

type fakeAgents struct {
	mu          sync.Mutex
	users       []string
	installs    int
	uninstalled bool
	starts      []string // "user" or "user!restart"
	stops       []string
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
	return nil
}
func (f *fakeAgents) Stop(u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, u)
	return nil
}

func TestAgentSupervisor(t *testing.T) {
	fa := &fakeAgents{users: []string{"alice"}}
	s := newAgentSupervisor(NewHub("unused", &recordingSink{}), fa)

	s.reconcile()
	s.reconcile()
	// First start after the service starts replaces an old helper (it may
	// run the binary from before a self-update); later ones just start.
	if !slices.Equal(fa.starts, []string{"alice!restart"}) || fa.installs != 1 {
		t.Fatalf("starts = %v installs = %d", fa.starts, fa.installs)
	}

	fa.users = []string{"alice", "bob"}
	s.reconcile()
	if !slices.Equal(fa.starts, []string{"alice!restart", "bob"}) {
		t.Errorf("starts = %v, want bob started once", fa.starts)
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
