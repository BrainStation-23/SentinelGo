package dlp

import (
	"context"
	"sync"
	"testing"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
)

// fakeFiles is a file DLP enforcer that records what the Manager asked.
type fakeFiles struct {
	mu      sync.Mutex
	applied int
	stops   int
	last    *policy.Compiled
}

func (f *fakeFiles) Apply(_ context.Context, c *policy.Compiled) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied++
	f.last = c
}

func (f *fakeFiles) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeFiles) Wants(m policy.FilesModule) bool {
	return m.ChannelEnabled(policy.ChannelFileRemovable)
}

func (f *fakeFiles) Capabilities() map[string]string {
	return map[string]string{policy.ChannelFileRemovable: "supported"}
}

func (f *fakeFiles) Health() *filedlp.Health { return &filedlp.Health{State: "running", Mounts: 1} }

func (f *fakeFiles) counts() (applied, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied, f.stops
}

func filesBundle(clipboard, files bool) *policy.Bundle {
	b := bundle(true, clipboard, "v-files")
	b.Modules.Files = policy.FilesModule{Enabled: files, Channels: map[string]bool{policy.ChannelFileRemovable: true}}
	return b
}

// With a file hook, a bundle that only enables file channels enforces files
// and leaves the clipboard helpers without a policy.
func TestManager_FilesOnly(t *testing.T) {
	sup, files := &fakeSupervisor{}, &fakeFiles{}
	m := NewManager(true, fakeSource{b: filesBundle(false, true)}, sup)
	m.SetFiles(files)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.State() != StateEnforcing {
		t.Fatalf("state %s", m.State())
	}
	if a, s := sup.counts(); a != 0 || s != 1 {
		t.Errorf("clipboard helpers: %d applies, %d stops", a, s)
	}
	if a, _ := files.counts(); a != 1 || files.last == nil || files.last.Version != "v-files" {
		t.Errorf("files: %d applies, last %v", a, files.last)
	}
	snap := m.Snapshot()
	if snap.FileCapabilities[policy.ChannelFileRemovable] != "supported" || snap.Files == nil || snap.Files.Mounts != 1 {
		t.Errorf("snapshot %+v", snap)
	}

	// Both on: helpers and files get the policy.
	m.Apply(filesBundle(true, true))
	if a, _ := sup.counts(); a != 1 {
		t.Errorf("clipboard helpers not applied (%d)", a)
	}
	// Files turned off, clipboard on: the enforcer is told (it stops itself).
	m.Apply(filesBundle(true, false))
	if a, _ := files.counts(); a != 3 {
		t.Errorf("files applies %d", a)
	}
	// Org kill switch: everything stops.
	m.Apply(bundle(false, true, "v-off"))
	if _, s := files.counts(); s != 1 || m.State() != StateDisabledServer {
		t.Errorf("files stops %d, state %s", s, m.State())
	}
	m.Stop()
	if _, s := files.counts(); s != 2 {
		t.Errorf("files stops after Stop: %d", s)
	}
}

// Without a file hook (every platform but Linux), file channels change
// nothing: a files-only bundle stays idle as before.
func TestManager_FilesWithoutHook(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: filesBundle(false, true)}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.State() != StateIdle {
		t.Errorf("state %s", m.State())
	}
	if snap := m.Snapshot(); snap.FileCapabilities != nil || snap.Files != nil {
		t.Errorf("snapshot %+v", snap)
	}
}

// The status carries the file capabilities and health.
func TestStatus_IncludesFiles(t *testing.T) {
	s := &Syncer{agentVersion: "1"}
	st, _ := s.status(Snapshot{State: StateEnforcing, FileCapabilities: map[string]string{policy.ChannelFileRemovable: "supported"},
		Files: &filedlp.Health{State: "running"}})
	if st.Capabilities[policy.ChannelFileRemovable] != "supported" || st.Files == nil || st.Files.State != "running" {
		t.Errorf("status %+v", st)
	}
	st, _ = s.status(Snapshot{State: StateEnforcing})
	if st.Files != nil {
		t.Error("files block without a hook")
	}
}
