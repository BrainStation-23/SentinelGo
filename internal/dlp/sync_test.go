package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/session"
)

// scriptedFetcher answers polls from a script and records each call.
type scriptedFetcher struct {
	replies []func(known string, st *Status) (FetchResult, error)
	calls   []fetchCall
}

type fetchCall struct {
	known  string
	status *Status
}

func (f *scriptedFetcher) FetchPolicy(_ context.Context, known string, st *Status) (FetchResult, error) {
	f.calls = append(f.calls, fetchCall{known, st})
	i := min(len(f.calls), len(f.replies)) - 1
	return f.replies[i](known, st)
}

func bundleJSON(version string, enabled bool, pollSeconds int) []byte {
	return fmt.Appendf(nil, `{"schema_version":1,"version":%q,"enabled":%v,"poll_interval_seconds":%d,
		"modules":{"clipboard":{"enabled":true}},
		"policies":[{"id":"p1","name":"n","channels":["clipboard"],"action":"block",
		  "detectors":[{"id":"secrets.all","rule_id":"r1","min_count":1},
		               {"id":"custom.regex","rule_id":"r-bad","pattern":"("}]}]}`, version, enabled, pollSeconds)
}

func newBundle(raw []byte) func(string, *Status) (FetchResult, error) {
	return func(string, *Status) (FetchResult, error) { return FetchResult{Raw: raw}, nil }
}

func unchanged(string, *Status) (FetchResult, error) { return FetchResult{Unchanged: true}, nil }

type syncFixture struct {
	cache *policy.Cache
	sup   *fakeSupervisor
	mgr   *Manager
	f     *scriptedFetcher
	s     *Syncer
	now   time.Time
}

func newSyncFixture(t *testing.T, cachePath string, replies ...func(string, *Status) (FetchResult, error)) *syncFixture {
	t.Helper()
	fx := &syncFixture{cache: policy.NewCache(cachePath), sup: &fakeSupervisor{}, now: time.Unix(1_700_000_000, 0)}
	fx.mgr = NewManager(true, fx.cache, fx.sup)
	if err := fx.mgr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.f = &scriptedFetcher{replies: replies}
	fx.s = NewSyncer(fx.f, fx.cache, fx.mgr, "9.9.9", func(Snapshot) map[string]string {
		return map[string]string{"clipboard": "unsupported:not_implemented"}
	})
	fx.s.now = func() time.Time { return fx.now }
	return fx
}

func TestSync_NewBundleCachedAndApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)))

	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := fx.mgr.State(); got != StateEnforcing {
		t.Errorf("state = %s, want enforcing", got)
	}
	cached, err := fx.cache.Load()
	if err != nil || cached == nil || cached.Version != "v1" {
		t.Fatalf("cache = %+v, %v", cached, err)
	}

	first := fx.f.calls[0]
	if first.known != "" || first.status == nil {
		t.Fatalf("first poll known=%q status=%v; want no version and a status", first.known, first.status)
	}
	st := first.status
	if st.AgentVersion != "9.9.9" || st.Capabilities["clipboard"] == "" || !slices.Contains(st.DetectorsSupported, "secrets.all") {
		t.Errorf("status = %+v", st)
	}
}

func TestSync_StatusReportsCompileErrorsAndIsSentOnlyWhenChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)), unchanged)

	for range 3 {
		fx.s.PollNow()
		if err := fx.s.Sync(context.Background()); err != nil {
			t.Fatalf("Sync: %v", err)
		}
	}
	calls := fx.f.calls
	// Poll 2 reports the applied version and the bad rule; poll 3 has nothing new.
	if calls[1].known != "v1" || calls[1].status == nil {
		t.Fatalf("second poll known=%q status=%v", calls[1].known, calls[1].status)
	}
	if calls[1].status.AppliedVersion != "v1" || len(calls[1].status.CompileErrors) != 1 || calls[1].status.CompileErrors[0].RuleID != "r-bad" {
		t.Errorf("second status = %+v", calls[1].status)
	}
	if len(calls[1].status.Sessions) != 1 {
		t.Errorf("sessions = %+v", calls[1].status.Sessions)
	}
	if calls[2].status != nil {
		t.Errorf("unchanged status re-sent: %+v", calls[2].status)
	}
}

func TestSync_UnchangedDoesNotRewriteCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)), unchanged)
	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	fx.s.PollNow()
	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Error("unchanged response rewrote the cache")
	}
}

// enabled:false is cached, so the org kill switch holds after an offline
// restart; a cached enabled bundle enforces at once on the next start.
// The status carries the Manager's state, and the capability fallback sees
// it, so "not enforcing" doesn't look like "helper failed to start".
func TestSync_StatusReportsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)), unchanged)
	var seen []State
	fx.s.capabilities = func(snap Snapshot) map[string]string {
		seen = append(seen, snap.State)
		return map[string]string{"clipboard": "unsupported:test"}
	}
	for range 2 {
		fx.s.PollNow()
		if err := fx.s.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	calls := fx.f.calls
	if calls[0].status == nil || calls[0].status.State != StateNoPolicy {
		t.Errorf("first status state = %+v, want no_policy", calls[0].status)
	}
	if calls[1].status == nil || calls[1].status.State != StateEnforcing {
		t.Errorf("second status state = %+v, want enforcing", calls[1].status)
	}
	if !slices.Equal(seen, []State{StateNoPolicy, StateEnforcing}) {
		t.Errorf("capabilities saw states %v", seen)
	}
	raw, _ := json.Marshal(calls[1].status)
	if !strings.Contains(string(raw), `"state":"enforcing"`) {
		t.Errorf("status JSON lacks state: %s", raw)
	}
}

// Helpers run while DLP is off too (for notify-user, #301): their reported
// capability counts only while enforcing, or the device would claim the
// clipboard is covered when it isn't.
func TestSync_HelperCapabilitiesOnlyWhileEnforcing(t *testing.T) {
	sup := &capsSupervisor{}
	m := NewManager(true, nil, sup)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := NewSyncer(&scriptedFetcher{}, policy.NewCache(filepath.Join(t.TempDir(), policy.CacheFileName)), m, "9.9.9",
		func(Snapshot) map[string]string {
			return map[string]string{"clipboard": "unsupported:dlp_not_enforcing"}
		})
	st, _ := s.status(m.Snapshot())
	if st.State != StateNoPolicy || st.Capabilities["clipboard"] != "unsupported:dlp_not_enforcing" {
		t.Errorf("not enforcing: state %s, clipboard %q", st.State, st.Capabilities["clipboard"])
	}
	m.Apply(newBundleT(t, bundleJSON("v1", true, 300)))
	st, _ = s.status(m.Snapshot())
	if st.State != StateEnforcing || st.Capabilities["clipboard"] != "supported" {
		t.Errorf("enforcing: state %s, clipboard %q", st.State, st.Capabilities["clipboard"])
	}
}

// capsSupervisor has one connected helper that supports the clipboard.
type capsSupervisor struct{ fakeSupervisor }

func (*capsSupervisor) Sessions() []session.Info {
	return []session.Info{{User: "alice", State: "idle", Capabilities: map[string]string{"clipboard": "supported"}}}
}

func newBundleT(t *testing.T, raw []byte) *policy.Bundle {
	t.Helper()
	b, err := policy.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSync_KillSwitchSurvivesOfflineRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)), newBundle(bundleJSON("v2", false, 300)))
	for range 2 {
		fx.s.PollNow()
		if err := fx.s.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := fx.mgr.State(); got != StateDisabledServer {
		t.Fatalf("state = %s, want disabled_server", got)
	}

	restarted := NewManager(true, policy.NewCache(path), &fakeSupervisor{})
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := restarted.State(); got != StateDisabledServer {
		t.Errorf("after offline restart state = %s, want disabled_server", got)
	}
}

func TestSync_OfflineStartWithCacheEnforces(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	b, err := policy.Decode(bundleJSON("v1", true, 300))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.NewCache(path).Save(b); err != nil {
		t.Fatal(err)
	}
	offline := func(string, *Status) (FetchResult, error) {
		return FetchResult{}, errors.New("dial tcp: no route to host")
	}
	fx := newSyncFixture(t, path, offline)

	if got := fx.mgr.State(); got != StateEnforcing {
		t.Fatalf("state before any poll = %s, want enforcing from the cache", got)
	}
	if err := fx.s.Sync(context.Background()); err == nil {
		t.Error("Sync returned nil for a failed poll")
	}
	if got := fx.mgr.State(); got != StateEnforcing {
		t.Errorf("state after failed poll = %s, want still enforcing", got)
	}
	if len(fx.sup.applied) != 1 || fx.sup.stops != 0 {
		t.Errorf("helpers applied=%d stops=%d, want 1/0", len(fx.sup.applied), fx.sup.stops)
	}
}

func TestSync_UnsupportedSchemaKeepsBundleAndIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	newer := []byte(`{"schema_version":2,"version":"v2","enabled":false}`)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 300)), newBundle(newer), unchanged)
	for i := range 3 {
		fx.s.PollNow()
		err := fx.s.Sync(context.Background())
		if (i == 1) != (err != nil) {
			t.Fatalf("poll %d: err = %v", i, err)
		}
	}
	if got := fx.mgr.State(); got != StateEnforcing {
		t.Errorf("state = %s; an unreadable bundle must not replace v1", got)
	}
	if cached, _ := fx.cache.Load(); cached.Version != "v1" {
		t.Errorf("cache = %s, want v1 kept", cached.Version)
	}
	st := fx.f.calls[2].status
	if st == nil || len(st.CompileErrors) == 0 || st.CompileErrors[0].RuleID != "" {
		t.Fatalf("third poll status = %+v; want the schema problem reported", st)
	}
}

func TestSync_StatusRejectedRetriesWithoutStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, func(_ string, st *Status) (FetchResult, error) {
		if st != nil {
			return FetchResult{}, fmt.Errorf("%w: 22023", ErrStatusRejected)
		}
		return FetchResult{Raw: bundleJSON("v1", true, 300)}, nil
	})
	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(fx.f.calls) != 2 || fx.f.calls[1].status != nil {
		t.Errorf("calls = %+v, want a retry without status", fx.f.calls)
	}
	if got := fx.mgr.State(); got != StateEnforcing {
		t.Errorf("state = %s", got)
	}
}

func TestSync_ScheduleFollowsPollInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), policy.CacheFileName)
	fx := newSyncFixture(t, path, newBundle(bundleJSON("v1", true, 10)), unchanged) // 10 s clamps to 60 s
	if !fx.s.Due() {
		t.Fatal("first poll not due")
	}
	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(59 * time.Second)
	if fx.s.Due() {
		t.Error("due before the clamped 60 s interval")
	}
	fx.now = fx.now.Add(7 * time.Second) // 66 s: past 60 s + max 10% jitter
	if !fx.s.Due() {
		t.Error("not due after interval + jitter")
	}
	if err := fx.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.s.PollNow()
	if !fx.s.Due() {
		t.Error("PollNow didn't make a poll due")
	}
}

// Helpers' capabilities override the service's guess: supported if any
// helper supports a channel, else the first reason reported.
func TestMergeHelperCapabilities(t *testing.T) {
	caps := map[string]string{"clipboard": "unsupported:no_graphical_session"}
	mergeHelperCapabilities(caps, []session.Info{
		{User: "a", Capabilities: map[string]string{"clipboard": "unsupported:wayland_no_data_control"}},
		{User: "b", Capabilities: map[string]string{"clipboard": "supported"}},
		{User: "c"},
	})
	if caps["clipboard"] != "supported" {
		t.Errorf("caps = %v", caps)
	}
	caps = map[string]string{"clipboard": "unsupported:no_graphical_session"}
	mergeHelperCapabilities(caps, []session.Info{{Capabilities: map[string]string{"clipboard": "unsupported:no_xclip_or_xsel"}}})
	if caps["clipboard"] != "unsupported:no_xclip_or_xsel" {
		t.Errorf("caps = %v", caps)
	}
}
