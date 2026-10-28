package dlp

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/dlp/policy"
)

// fakeSource is a BundleSource returning a fixed bundle or error.
type fakeSource struct {
	b   *policy.Bundle
	err error
}

func (f fakeSource) Load() (*policy.Bundle, error) { return f.b, f.err }

// fakeSupervisor records what the Manager asked of the helpers.
type fakeSupervisor struct {
	mu      sync.Mutex
	applied []*policy.Compiled
	stops   int
}

func (f *fakeSupervisor) Apply(_ context.Context, p *policy.Compiled) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, p)
}

func (f *fakeSupervisor) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeSupervisor) counts() (applied, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied), f.stops
}

func bundle(enabled, clipboard bool, version string) *policy.Bundle {
	return &policy.Bundle{
		SchemaVersion: policy.SchemaVersion,
		Version:       version,
		Enabled:       enabled,
		Modules:       policy.Modules{Clipboard: policy.ClipboardModule{Enabled: clipboard}},
	}
}

// captureLog redirects the standard logger for the test and returns the buffer.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func TestDecide_TruthTable(t *testing.T) {
	tests := []struct {
		name  string
		local bool
		b     *policy.Bundle
		want  State
	}{
		{"local off wins over enabled bundle", false, bundle(true, true, "v1"), StateDisabledLocal},
		{"local off with no bundle", false, nil, StateDisabledLocal},
		{"no bundle ever fetched is off", true, nil, StateNoPolicy},
		{"org kill switch", true, bundle(false, true, "v1"), StateDisabledServer},
		{"org kill switch with clipboard off", true, bundle(false, false, "v1"), StateDisabledServer},
		{"clipboard module off", true, bundle(true, false, "v1"), StateIdle},
		{"enforcing", true, bundle(true, true, "v1"), StateEnforcing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.local, tt.b); got != tt.want {
				t.Errorf("Decide(%v, …) = %s, want %s", tt.local, got, tt.want)
			}
		})
	}
}

func TestManager_LocalDisabledStartsNothing(t *testing.T) {
	buf := captureLog(t)
	sup := &fakeSupervisor{}
	m := NewManager(false, fakeSource{b: bundle(true, true, "v1")}, sup)

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Apply(bundle(true, true, "v2"))
	m.Stop()

	if applied, stops := sup.counts(); applied != 0 || stops != 0 {
		t.Errorf("supervisor applied=%d stops=%d, want 0/0", applied, stops)
	}
	if got := m.State(); got != StateDisabledLocal {
		t.Errorf("State = %s, want %s", got, StateDisabledLocal)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "dlp_enabled=false") {
		t.Errorf("want exactly one log line naming dlp_enabled=false, got %q", buf.String())
	}
}

func TestManager_NoCachedBundleStaysOff(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, nil, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if applied, _ := sup.counts(); applied != 0 {
		t.Errorf("applied = %d, want 0", applied)
	}
	if got := m.State(); got != StateNoPolicy {
		t.Errorf("State = %s, want %s", got, StateNoPolicy)
	}
}

func TestManager_CachedBundleEnforcesAtStart(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "v1")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := m.State(); got != StateEnforcing {
		t.Fatalf("State = %s, want %s", got, StateEnforcing)
	}
	if len(sup.applied) != 1 || sup.applied[0].Version != "v1" {
		t.Errorf("applied = %+v, want one apply of v1", sup.applied)
	}
}

func TestManager_SourceErrorIsNoPolicy(t *testing.T) {
	captureLog(t)
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{err: errors.New("corrupt cache")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := m.State(); got != StateNoPolicy {
		t.Errorf("State = %s, want %s", got, StateNoPolicy)
	}
}

func TestManager_OrgKillSwitchStopsHelpers(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "v1")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, stopsBefore := sup.counts()

	m.Apply(bundle(false, true, "v2"))

	if got := m.State(); got != StateDisabledServer {
		t.Errorf("State = %s, want %s", got, StateDisabledServer)
	}
	if applied, stops := sup.counts(); applied != 1 || stops != stopsBefore+1 {
		t.Errorf("applied=%d stops=%d, want 1 apply and one more stop", applied, stops)
	}
}

func TestManager_ClipboardModuleOffIsIdle(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "v1")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Apply(bundle(true, false, "v2"))

	if got := m.State(); got != StateIdle {
		t.Errorf("State = %s, want %s", got, StateIdle)
	}
	if _, stops := sup.counts(); stops == 0 {
		t.Error("helpers were not stopped when the clipboard module turned off")
	}
}

func TestManager_FailedFetchKeepsLastKnown(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "v1")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Apply(nil) // what a failed fetch amounts to

	if got := m.State(); got != StateEnforcing {
		t.Errorf("State = %s, want %s", got, StateEnforcing)
	}
	if applied, stops := sup.counts(); applied != 1 || stops != 0 {
		t.Errorf("applied=%d stops=%d, want 1/0", applied, stops)
	}
}

func TestManager_NewBundlePushedToHelpers(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, nil, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Apply(bundle(true, true, "v1"))
	m.Apply(bundle(true, true, "v2"))

	if len(sup.applied) != 2 || sup.applied[1].Version != "v2" {
		t.Errorf("applied = %+v, want v1 then v2", sup.applied)
	}
}

func TestManager_ApplyBeforeStartIsUsedByStart(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "cached")}, sup)
	m.Apply(bundle(true, true, "fresh"))
	if applied, _ := sup.counts(); applied != 0 {
		t.Fatalf("Apply before Start reached the supervisor")
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(sup.applied) != 1 || sup.applied[0].Version != "fresh" {
		t.Errorf("applied = %+v, want the fresh bundle", sup.applied)
	}
}

func TestManager_StopThenApplyDoesNotRestartHelpers(t *testing.T) {
	sup := &fakeSupervisor{}
	m := NewManager(true, fakeSource{b: bundle(true, true, "v1")}, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Stop()
	m.Apply(bundle(true, true, "v2"))

	if applied, stops := sup.counts(); applied != 1 || stops != 1 {
		t.Errorf("applied=%d stops=%d, want 1/1", applied, stops)
	}
	if got := m.State(); got != StateStopped {
		t.Errorf("State = %s, want %s", got, StateStopped)
	}
	m.Stop() // idempotent
}
