package ruleset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
)

// secretMarker is in every rule source; it must never reach a log.
const secretMarker = "RULE-SOURCE-MARKER-91c2"

const (
	rsA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	rsB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func ruleSource(name string) []byte {
	return fmt.Appendf(nil, "rule %s { strings: $a = %q condition: $a }\n", name, secretMarker)
}

type fakeServer struct {
	mu       sync.Mutex
	bundle   []byte // nil: unchanged
	objects  map[string][]byte
	known    []string
	statuses []*yara.Status
	reject   bool // 22023 on a status
	fetchErr error
}

func (f *fakeServer) FetchRuleset(_ context.Context, known string, st *yara.Status) (FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.known = append(f.known, known)
	f.statuses = append(f.statuses, st)
	if f.fetchErr != nil {
		return FetchResult{}, f.fetchErr
	}
	if st != nil && f.reject {
		return FetchResult{}, ErrStatusRejected
	}
	if f.bundle == nil || bundleVersion(f.bundle) == known {
		return FetchResult{}, nil
	}
	return FetchResult{Changed: true, Raw: f.bundle}, nil
}

func (f *fakeServer) DownloadRuleset(_ context.Context, path string, w io.Writer, limit int64) error {
	f.mu.Lock()
	data, ok := f.objects[path]
	f.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if int64(len(data)) > limit {
		_, _ = w.Write(data[:limit])
		return ErrTooLarge
	}
	_, err := w.Write(data)
	return err
}

func bundleVersion(raw []byte) string {
	var v struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Version
}

// engineCompiler compiles in-process (the production Compiler uses a worker).
type engineCompiler struct{ calls int }

func (c *engineCompiler) Compile(ctx context.Context, srcs []yara.RuleSource) (Rules, []yara.CompileResult, error) {
	c.calls++
	e := engine.New(engine.Options{})
	var out []yara.CompileResult
	progs := map[string]engine.Program{}
	for _, s := range srcs {
		p, skipped, err := e.Compile(ctx, s.ID, s.Source)
		r := yara.CompileResult{ID: s.ID, Revision: s.Revision, Skipped: skipped}
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Rules = p.RuleCount()
			progs[s.ID] = p
		}
		out = append(out, r)
	}
	return progs, out, nil
}

type rs struct {
	id   string
	rev  int
	data []byte
}

func makeBundle(version string, enabled bool, sets ...rs) ([]byte, map[string][]byte) {
	objects := map[string][]byte{}
	var list []map[string]any
	for _, r := range sets {
		sum := sha256.Sum256(r.data)
		p := fmt.Sprintf("yara/default/%s/%d.yar", r.id, r.rev)
		objects[p] = r.data
		list = append(list, map[string]any{"id": r.id, "name": "n", "revision": r.rev, "storage_path": p,
			"sha256": hex.EncodeToString(sum[:]), "size": len(r.data), "severity": "high"})
	}
	b, _ := json.Marshal(map[string]any{"schema_version": 1, "version": version, "enabled": enabled,
		"engine": map[string]any{"name": "go-yara", "min_version": "0.9.0"}, "rulesets": list, "schedules": []any{},
		"limits": map[string]any{}, "evidence": map[string]any{"path_mode": "hashed"}})
	return b, objects
}

type harness struct {
	srv     *fakeServer
	comp    *engineCompiler
	cache   *Cache
	changes []*Active
	s       *Syncer
}

func newHarness(t *testing.T, dir string) *harness {
	t.Helper()
	h := &harness{srv: &fakeServer{objects: map[string][]byte{}}, comp: &engineCompiler{}, cache: NewCache(filepath.Join(dir, DirName))}
	h.s = New(Options{Fetcher: h.srv, Downloader: h.srv, Compiler: h.comp, Cache: h.cache,
		AgentVersion: "9.9.9", EngineVersion: "0.9.0", OnChange: func(a *Active) { h.changes = append(h.changes, a) }})
	return h
}

func (h *harness) publish(raw []byte, objects map[string][]byte) {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	h.srv.bundle = raw
	for k, v := range objects {
		h.srv.objects[k] = v
	}
}

func TestSync_UnchangedThenChanged(t *testing.T) {
	h := newHarness(t, t.TempDir())
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.s.Active() != nil || len(h.changes) != 0 || h.s.Status().State != yara.StateDisabled {
		t.Fatalf("nothing published: active %+v status %+v", h.s.Active(), h.s.Status())
	}
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}, rs{rsB, 3, []byte("import \"pe\"\nrule p { condition: pe.is_dll() }\n" + string(ruleSource("b")))}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := h.s.Active()
	if !a.Enabled() || a.Bundle.Version != "v1" || a.Revision(rsB) != 3 || len(h.changes) != 1 {
		t.Fatalf("active %+v", a)
	}
	st := h.s.Status()
	if st.State != yara.StateOK || st.AppliedVersion != "v1" || len(st.Rulesets) != 2 ||
		st.Rulesets[1].CompiledRules != 1 || st.Rulesets[1].SkippedRules[0].Reason != "unsupported_module:pe" {
		t.Fatalf("status %+v", st)
	}
	// The next poll sends the applied version, and nothing is reapplied.
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.srv.known[len(h.srv.known)-1]; got != "v1" || len(h.changes) != 1 || h.comp.calls != 1 {
		t.Errorf("known %q, changes %d, compiles %d", got, len(h.changes), h.comp.calls)
	}
}

// The status goes out only when it changed since the server accepted it;
// a rejected status is dropped from that poll.
func TestSync_StatusSentOnChange(t *testing.T) {
	h := newHarness(t, t.TempDir())
	for range 2 {
		_ = h.s.Sync(context.Background())
	}
	if h.srv.statuses[0] == nil || h.srv.statuses[1] != nil {
		t.Fatalf("statuses %v", h.srv.statuses)
	}
	h.s.SetLastScan(&yara.ScanSummary{ScanID: yara.NewID(), State: yara.ScanCompleted})
	_ = h.s.Sync(context.Background())
	if h.srv.statuses[2] == nil || h.srv.statuses[2].LastScan == nil {
		t.Fatalf("changed status not sent: %+v", h.srv.statuses[2])
	}
	h.srv.reject = true
	h.s.SetLastScan(&yara.ScanSummary{ScanID: yara.NewID(), State: yara.ScanFailed})
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(h.srv.statuses); h.srv.statuses[n-2] == nil || h.srv.statuses[n-1] != nil {
		t.Fatalf("rejected status: %v", h.srv.statuses[n-2:])
	}
}

func TestSync_FailuresKeepLastGoodSet(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	good := h.s.Active()

	check := func(name, state string) {
		t.Helper()
		if err := h.s.Sync(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
		if h.s.Active() != good {
			t.Errorf("%s: the last good set was replaced", name)
		}
		if st := h.s.Status(); st.State != state || st.AppliedVersion != "v1" {
			t.Errorf("%s: status %+v", name, st)
		}
		if h.s.Due() {
			t.Errorf("%s: polls again at once", name)
		}
		h.s.mu.Lock()
		h.s.next = time.Time{}
		h.s.mu.Unlock()
	}

	// Hash mismatch: the object isn't what the bundle says.
	raw, objs := makeBundle("v2", true, rs{rsA, 2, ruleSource("a2")})
	for k := range objs {
		objs[k] = ruleSource("tampered")
	}
	h.publish(raw, objs)
	check("hash mismatch", yara.StateDownloadFailed)

	// Missing object (404).
	raw, _ = makeBundle("v3", true, rs{rsA, 3, ruleSource("a3")})
	h.publish(raw, nil)
	check("404", yara.StateDownloadFailed)

	// Bigger than the bundle says.
	raw, objs = makeBundle("v4", true, rs{rsA, 4, ruleSource("a4")})
	for k, v := range objs {
		objs[k] = append(v, "// more\n"...)
	}
	h.publish(raw, objs)
	check("larger object", yara.StateDownloadFailed)

	// Bundle over the contract's limits.
	var many []rs
	for i := range yara.MaxRulesets + 1 {
		many = append(many, rs{fmt.Sprintf("%08d-0000-4000-8000-000000000000", i), 1, ruleSource("x")})
	}
	h.publish(makeBundle("v5", true, many...))
	check("too many rulesets", yara.StateTooLarge)

	// Unknown schema.
	h.publish([]byte(`{"schema_version": 2, "version": "v6"}`), nil)
	check("schema", yara.StateUnsupportedSchema)

	// A ruleset that doesn't compile at all: compile_failed, with the reason
	// in the status.
	h.publish(makeBundle("v7", true, rs{rsA, 7, ruleSource("a7")}, rs{rsB, 1, []byte(`include "x.yar"`)}))
	check("compile", yara.StateCompileFailed)
	st := h.s.Status()
	if len(st.Rulesets) != 2 || st.Rulesets[1].SkippedRules[0].Rule != "(ruleset)" {
		t.Errorf("compile failure status %+v", st.Rulesets)
	}

	// Fixed: applied, state back to ok.
	h.publish(makeBundle("v8", true, rs{rsA, 8, ruleSource("a8")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := h.s.Status(); st.State != yara.StateOK || st.AppliedVersion != "v8" {
		t.Errorf("after fix: %+v", st)
	}
}

func TestSync_Disabled(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, DirName, bundleFile)); err != nil {
		t.Fatalf("not cached: %v", err)
	}
	h.publish(makeBundle("v2", false))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := h.s.Active()
	if a.Enabled() || a.Rules != nil || len(h.changes) != 2 || h.changes[1] != a {
		t.Fatalf("disabled: %+v", a)
	}
	if st := h.s.Status(); st.State != yara.StateDisabled || st.AppliedVersion != "v2" || len(st.Rulesets) != 0 {
		t.Errorf("status %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); !os.IsNotExist(err) {
		t.Errorf("cache not deleted: %v", err)
	}
}

// At startup the cached bundle applies before (and without) the network.
func TestSync_RestoreOffline(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	h2 := newHarness(t, dir)
	h2.srv.fetchErr = errors.New("offline")
	if err := h2.s.Sync(context.Background()); err == nil {
		t.Fatal("offline poll succeeded")
	}
	if a := h2.s.Active(); !a.Enabled() || a.Bundle.Version != "v1" || len(h2.changes) != 1 {
		t.Fatalf("restored %+v", a)
	}
	if h2.srv.known[0] != "v1" {
		t.Errorf("known %q", h2.srv.known[0])
	}
	if st := h2.s.Status(); st.State != yara.StateOK {
		t.Errorf("status %+v", st)
	}
}

// Restore applies the cached bundle without polling, once: a yara-scan task
// right after startup scans with the rules the device has.
func TestRestore_WithoutPoll(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h2 := newHarness(t, dir)
	h2.s.Restore(context.Background())
	h2.s.Restore(context.Background())
	if a := h2.s.Active(); !a.Enabled() || len(h2.srv.known) != 0 || h2.comp.calls != 1 {
		t.Fatalf("active %+v, polls %d, compiles %d", a, len(h2.srv.known), h2.comp.calls)
	}
	if err := h2.s.Sync(context.Background()); err != nil || h2.comp.calls != 1 {
		t.Fatalf("sync after restore: %v, compiles %d", err, h2.comp.calls)
	}
}

// A corrupt cache is deleted and the bundle is asked for from scratch.
func TestSync_CorruptCache(t *testing.T) {
	for name, corrupt := range map[string]func(dir string){
		"bundle": func(dir string) { _ = os.WriteFile(filepath.Join(dir, bundleFile), []byte("{nope"), 0o600) },
		"source": func(dir string) {
			ents, _ := os.ReadDir(filepath.Join(dir, rulesDir))
			_ = os.WriteFile(filepath.Join(dir, rulesDir, ents[0].Name()), []byte("rule x { condition: true }"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			h := newHarness(t, dir)
			h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
			if err := h.s.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			corrupt(filepath.Join(dir, DirName))

			h2 := newHarness(t, dir)
			h2.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
			if err := h2.s.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if h2.srv.known[0] != "" {
				t.Errorf("known %q, want empty after a corrupt cache", h2.srv.known[0])
			}
			if a := h2.s.Active(); !a.Enabled() || a.Bundle.Version != "v1" {
				t.Errorf("active %+v", a)
			}
		})
	}
}

func TestPollTiming(t *testing.T) {
	h := newHarness(t, t.TempDir())
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	h.s.now = func() time.Time { return now }
	if !h.s.Due() {
		t.Fatal("not due at startup")
	}
	_ = h.s.Sync(context.Background())
	if h.s.Due() {
		t.Fatal("due right after a poll")
	}
	h.s.PollNow()
	if h.s.Due() {
		t.Error("PollNow within 30 s of the last poll")
	}
	now = now.Add(minPollGap)
	if !h.s.Due() {
		t.Error("PollNow not due after the gap")
	}
	_ = h.s.Sync(context.Background())
	now = now.Add(PollInterval - time.Second)
	if h.s.Due() {
		t.Error("due before the interval")
	}
	now = now.Add(pollJitter + time.Second)
	if !h.s.Due() {
		t.Error("not due after interval + jitter")
	}
}

// 50 rulesets x 100 skipped rules with long names still fit the server's
// 64 KB status limit.
func TestStatusFitsLimit(t *testing.T) {
	h := newHarness(t, t.TempDir())
	var results []yara.CompileResult
	for i := range yara.MaxRulesets {
		r := yara.CompileResult{ID: fmt.Sprintf("%08d-0000-4000-8000-000000000000", i), Revision: 1, Rules: 10}
		for j := range yara.MaxSkippedRules {
			r.Skipped = append(r.Skipped, yara.SkippedRule{Rule: strings.Repeat("R", 200) + fmt.Sprint(j), Line: j, Reason: "unsupported_module:" + strings.Repeat("m", 100)})
		}
		results = append(results, r)
	}
	h.s.results = results
	st := h.s.Status()
	data, err := st.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > yara.MaxStatusBytes {
		t.Fatalf("status is %d bytes", len(data))
	}
}

// Nothing the Syncer logs, in success or failure, contains rule source.
func TestNoRuleSourceInLogs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	h := newHarness(t, t.TempDir())
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	_ = h.s.Sync(context.Background())
	bad := append(ruleSource("b"), []byte("rule broken { condition: ( }\n")...)
	h.publish(makeBundle("v2", true, rs{rsA, 2, bad}, rs{rsB, 1, []byte("include \"" + secretMarker + "\"")}))
	h.s.next = time.Time{}
	_ = h.s.Sync(context.Background())
	if buf.Len() == 0 {
		t.Fatal("nothing logged")
	}
	if strings.Contains(buf.String(), secretMarker) {
		t.Fatalf("rule source in the log:\n%s", buf.String())
	}
}

func TestCacheIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkOwnerOnly(t, filepath.Join(dir, DirName))
}

// yara_enabled false (#416): the device still polls and reports disabled,
// but never applies a bundle, compiles, or keeps a cache, and doesn't ask
// for the same bundle again.
func TestSync_LocallyDisabled(t *testing.T) {
	dir := t.TempDir()
	// A cache left from when it was on.
	on := newHarness(t, dir)
	on.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := on.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t, dir)
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	h.s.o.LocallyDisabled = true
	for range 2 {
		if err := h.s.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if h.s.Active() != nil || len(h.changes) != 0 || h.comp.calls != 0 {
		t.Fatalf("applied while locally disabled: active %+v, compiles %d", h.s.Active(), h.comp.calls)
	}
	if st := h.s.Status(); st.State != yara.StateDisabled || h.srv.statuses[0] == nil || h.srv.statuses[0].State != yara.StateDisabled {
		t.Fatalf("status %+v, sent %+v", st, h.srv.statuses[0])
	}
	if h.srv.known[1] != "v1" {
		t.Errorf("second poll known %q, want v1", h.srv.known[1])
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); !os.IsNotExist(err) {
		t.Errorf("ruleset cache kept: %v", err)
	}
}

// A scan refused folders by macOS privacy shows as tcc_denied, below the
// failure states.
func TestStatus_TCCDenied(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.publish(makeBundle("v1", true, rs{rsA, 1, ruleSource("a")}))
	if err := h.s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.s.SetTCCDenied(true)
	if st := h.s.Status(); st.State != yara.StateTCCDenied {
		t.Fatalf("state %q, want tcc_denied", st.State)
	}
	h.s.SetTCCDenied(false)
	if st := h.s.Status(); st.State != yara.StateOK {
		t.Fatalf("state %q, want ok", st.State)
	}
}
