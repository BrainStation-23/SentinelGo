package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
	"sentinelgo/internal/yara/report"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/walk"
)

const (
	rsA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	schedA = "5c4ed0a1-0000-4000-8000-00000000000a"
	agent  = "11111111-2222-4333-8444-555555555555"
	// marker stands in for EICAR, which Windows Defender quarantines.
	marker = "SENTINELOPS-YARA-TEST-MARKER-7F3A9C"
)

// fakeScanner matches files containing marker. With a gate it waits for a
// value (or ctx) before each file, so tests can hold a scan mid-way.
type fakeScanner struct {
	gate    chan struct{}
	mu      sync.Mutex
	scanned []string
	entered chan struct{} // receives once per file when set
}

func (s *fakeScanner) ScanFile(ctx context.Context, _ ruleset.Rules, f walk.File, _ []string, _ time.Duration) FileOutcome {
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return FileOutcome{Status: Skipped}
		}
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return FileOutcome{Status: ReadError}
	}
	s.mu.Lock()
	s.scanned = append(s.scanned, filepath.Base(f.Path))
	s.mu.Unlock()
	sum := sha256.Sum256(data)
	out := FileOutcome{Status: Scanned, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if bytes.Contains(data, []byte(marker)) {
		out.Matches = []engine.Match{{Rule: "test_marker", Namespace: rsA, StringIDs: []string{"$m"}}}
	}
	return out
}

type fakeQueue struct {
	mu  sync.Mutex
	evs []yara.Event
}

func (q *fakeQueue) Add(evs []yara.Event) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, ev := range evs {
		if err := ev.Validate(); err != nil {
			return err
		}
	}
	q.evs = append(q.evs, evs...)
	return nil
}

func (q *fakeQueue) summaries() []*yara.ScanSummary {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*yara.ScanSummary
	for _, ev := range q.evs {
		if ev.Summary != nil {
			out = append(out, ev.Summary)
		}
	}
	return out
}

func (q *fakeQueue) matches() []*yara.Match {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*yara.Match
	for _, ev := range q.evs {
		if ev.Match != nil {
			out = append(out, ev.Match)
		}
	}
	return out
}

func bundle(schedules ...yara.Schedule) *ruleset.Active {
	return &ruleset.Active{Rules: "compiled", Bundle: &yara.Bundle{
		SchemaVersion: 1, Version: "v1", Enabled: true,
		Rulesets:  []yara.Ruleset{{ID: rsA, Revision: 4}},
		Schedules: schedules,
		Limits:    yara.Limits{MaxFileBytes: 1 << 20, PerFileTimeoutMS: 1000, MaxFilesPerScan: 1000, MaxScanMinutes: 60},
		Evidence:  yara.Evidence{PathMode: yara.PathModeFull},
	}}
}

func customSchedule(dir string) yara.Schedule {
	s := yara.Schedule{ID: schedA, Preset: yara.PresetCustom, EveryHours: 24, JitterMinutes: 0}
	switch runtime.GOOS {
	case "windows":
		s.Paths.Windows = []string{dir}
	case "darwin":
		s.Paths.Darwin = []string{dir}
	default:
		s.Paths.Linux = []string{dir}
	}
	return s
}

func files(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		content := "harmless " + n
		if strings.HasPrefix(n, "bad") {
			content = "x " + marker + " y"
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type rig struct {
	r       *Runner
	q       *fakeQueue
	sc      FileScanner
	active  *ruleset.Active
	mu      sync.Mutex
	ended   []*yara.ScanSummary
	now     time.Time
	state   string
	polled  int
	endedCh chan *yara.ScanSummary
}

func newRig(t *testing.T, a *ruleset.Active, sc FileScanner) *rig {
	t.Helper()
	dir := t.TempDir()
	g := &rig{q: &fakeQueue{}, sc: sc, active: a, now: time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC),
		state: filepath.Join(dir, StateFileName), endedCh: make(chan *yara.ScanSummary, 16)}
	g.r = g.runner(filepath.Join(dir, SkipCacheFileName))
	return g
}

func (g *rig) runner(cachePath string) *Runner {
	return New(Options{
		Active:  func() *ruleset.Active { g.mu.Lock(); defer g.mu.Unlock(); return g.active },
		Scanner: g.sc, Queue: g.q, AgentID: agent, StatePath: g.state, SkipCachePath: cachePath,
		Env:            walk.DefaultEnv(),
		BeforeOnDemand: func() { g.mu.Lock(); g.polled++; g.mu.Unlock() },
		OnScanEnd: func(s *yara.ScanSummary, _ bool) {
			g.mu.Lock()
			g.ended = append(g.ended, s)
			g.mu.Unlock()
			g.endedCh <- s
		},
		Now: func() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.now },
	})
}

func (g *rig) advance(d time.Duration) {
	g.mu.Lock()
	g.now = g.now.Add(d)
	g.mu.Unlock()
}

func (g *rig) waitEnd(t *testing.T) *yara.ScanSummary {
	t.Helper()
	select {
	case s := <-g.endedCh:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not end")
		return nil
	}
}

func waitIdle(t *testing.T, r *Runner) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.Current() != nil {
		if time.Now().After(deadline) {
			t.Fatal("runner still busy")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOffset_DeterministicAndBounded(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := range 200 {
		id := yara.NewID()
		o := Offset(id, schedA, 120)
		if o < 0 || o >= 120*time.Minute {
			t.Fatalf("offset %v out of [0, 120m)", o)
		}
		if Offset(id, schedA, 120) != o {
			t.Fatal("offset not stable for the same agent")
		}
		seen[o] = true
		_ = i
	}
	if len(seen) < 150 {
		t.Errorf("only %d distinct offsets over 200 agents", len(seen))
	}
	if Offset(agent, schedA, 0) != 0 {
		t.Error("jitter 0 must mean no offset")
	}
	if Offset(agent, schedA, 60) == Offset(agent, "5c4ed0a1-0000-4000-8000-00000000000b", 60) &&
		Offset(agent, schedA, 600) == Offset(agent, "5c4ed0a1-0000-4000-8000-00000000000b", 600) {
		t.Error("schedules of one agent share an offset")
	}
}

func TestNextRun(t *testing.T) {
	s := yara.Schedule{ID: schedA, EveryHours: 6, JitterMinutes: 90}
	off := Offset(agent, schedA, 90)
	seen := time.Date(2026, 11, 11, 10, 17, 0, 0, time.UTC)
	if got := NextRun(s, agent, seen, time.Time{}); !got.Equal(seen.Add(off)) {
		t.Fatalf("first run %v, want %v", got, seen.Add(off))
	}
	last := time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC)
	next := NextRun(s, agent, seen, last)
	if !next.After(last) || next.Sub(last) > 6*time.Hour {
		t.Fatalf("next %v after last %v", next, last)
	}
	if rem := next.Sub(time.Unix(0, 0).Add(off)) % (6 * time.Hour); rem != 0 {
		t.Fatalf("next %v is not on the device's period boundary (rem %v)", next, rem)
	}
	if again := NextRun(s, agent, seen, next); !again.Equal(next.Add(6 * time.Hour)) {
		t.Fatalf("after running at %v, next %v", next, again)
	}
}

func TestOnDemand_ScansAndReports(t *testing.T) {
	dir := files(t, "a.txt", "bad.bin", "c.txt")
	g := newRig(t, bundle(), &fakeScanner{})
	res, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}, Reason: "test"})
	if err != nil || res.State != yara.TaskStarted || !yara.IsUUID(res.ScanID) {
		t.Fatalf("result %+v, %v", res, err)
	}
	sum := g.waitEnd(t)
	waitIdle(t, g.r)
	if sum.ScanID != res.ScanID || sum.State != yara.ScanCompleted || sum.Trigger != yara.TriggerOnDemand ||
		sum.FilesScanned != 3 || sum.Matches != 1 || sum.Preset != yara.PresetCustom {
		t.Fatalf("summary %+v", sum)
	}
	ms := g.q.matches()
	want := sha256.Sum256([]byte("x " + marker + " y"))
	if len(ms) != 1 || ms[0].SHA256 != hex.EncodeToString(want[:]) || ms[0].RulesetID != rsA ||
		ms[0].RulesetRevision != 4 || ms[0].Path == nil || filepath.Base(*ms[0].Path) != "bad.bin" {
		t.Fatalf("matches %+v", ms)
	}
	if len(g.q.summaries()) != 1 || g.polled != 1 {
		t.Errorf("summaries %d, polls requested %d", len(g.q.summaries()), g.polled)
	}
	if ls := g.r.LastScan(); ls == nil || ls.ScanID != res.ScanID {
		t.Errorf("last scan %+v", ls)
	}
}

// The server's scan id is used as is.
func TestOnDemand_UsesServerScanID(t *testing.T) {
	dir := files(t, "a.txt")
	g := newRig(t, bundle(), &fakeScanner{})
	id := yara.NewID()
	res, err := g.r.StartOnDemand(yara.TaskParams{ScanID: id, Preset: yara.PresetCustom, Paths: []string{dir}})
	if err != nil || res.ScanID != id {
		t.Fatalf("result %+v, %v", res, err)
	}
	if sum := g.waitEnd(t); sum.ScanID != id {
		t.Fatalf("summary scan id %s", sum.ScanID)
	}
}

func TestOnDemand_InvalidScopeStartsNothing(t *testing.T) {
	dir := files(t, "a.txt")
	g := newRig(t, bundle(), &fakeScanner{})
	cases := []struct {
		name string
		p    yara.TaskParams
		want error
	}{
		{"missing folder", yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{filepath.Join(dir, "nope")}}, ErrNoPaths},
		{"relative folder", yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{"relative/dir"}}, ErrNoPaths},
		{"unknown ruleset", yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}, RulesetIDs: []string{yara.NewID()}}, ErrNoRulesets},
	}
	for _, tc := range cases {
		if _, err := g.r.StartOnDemand(tc.p); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
	}
	g.active = &ruleset.Active{Bundle: &yara.Bundle{Version: "off"}}
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled: %v", err)
	}
	if g.r.Current() != nil || len(g.q.evs) != 0 {
		t.Fatal("a scan started")
	}
}

func TestOnDemand_BusyAndCancel(t *testing.T) {
	dir := files(t, "a.txt", "b.txt")
	sc := &fakeScanner{gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	g := newRig(t, bundle(), sc)
	first, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	<-sc.entered
	second, err := g.r.StartOnDemand(yara.TaskParams{ScanID: yara.NewID(), Preset: yara.PresetCustom, Paths: []string{dir}})
	if err != nil || second.State != yara.TaskBusy || second.RunningScanID != first.ScanID || second.ScanID == first.ScanID {
		t.Fatalf("second %+v, %v", second, err)
	}
	if got := g.r.Cancel(); got != first.ScanID {
		t.Fatalf("cancelled %q", got)
	}
	sum := g.waitEnd(t)
	if sum.State != yara.ScanCancelled || sum.ScanID != first.ScanID {
		t.Fatalf("summary %+v", sum)
	}
	if g.r.Current() != nil || g.r.Cancel() != "" {
		t.Fatal("still running after cancel")
	}
}

// An on-demand scan stops a scheduled one, which then continues under the
// same scan id from where it stopped.
func TestScheduled_PreemptedThenResumed(t *testing.T) {
	dir := files(t, "a.txt", "b.txt", "bad.txt", "d.txt")
	sc := &fakeScanner{gate: make(chan struct{}, 10), entered: make(chan struct{}, 1)}
	g := newRig(t, bundle(customSchedule(dir)), sc)
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	cur := g.r.Current()
	if cur == nil || cur.Trigger != yara.TriggerScheduled {
		t.Fatalf("scheduled scan not started: %+v", cur)
	}
	sc.gate <- struct{}{} // a.txt
	<-sc.entered
	<-sc.entered // waiting at b.txt
	od := files(t, "x.txt")
	res, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{od}})
	if err != nil || res.State != yara.TaskStarted {
		t.Fatalf("on-demand %+v, %v", res, err)
	}
	sc.gate <- struct{}{}
	if s := g.waitEnd(t); s.ScanID != res.ScanID {
		t.Fatalf("first summary is %+v, want the on-demand scan", s)
	}
	waitIdle(t, g.r)
	if n := len(g.q.summaries()); n != 1 {
		t.Fatalf("%d summaries; the preempted scan must not send one", n)
	}
	// The next tick continues the scheduled scan.
	for range 4 {
		sc.gate <- struct{}{}
	}
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	if c := g.r.Current(); c == nil || c.ScanID != cur.ScanID {
		t.Fatalf("resumed %+v, want scan %s", c, cur.ScanID)
	}
	s := g.waitEnd(t)
	if s.ScanID != cur.ScanID || s.State != yara.ScanCompleted || s.FilesScanned != 4 || s.Matches != 1 {
		t.Fatalf("resumed summary %+v", s)
	}
	// It doesn't run again this period.
	waitIdle(t, g.r)
	if err := g.r.Tick(); err != nil || g.r.Current() != nil {
		t.Fatalf("ran again: %+v %v", g.r.Current(), err)
	}
	g.advance(25 * time.Hour)
	if err := g.r.Tick(); err != nil || g.r.Current() == nil {
		t.Fatalf("not due after a period: %v", err)
	}
	waitIdle(t, g.r)
}

// Service stop: the scan is checkpointed, no goroutine is left, and a new
// runner continues it after the restart.
func TestScheduled_ShutdownCheckpointAndResume(t *testing.T) {
	dir := files(t, "a.txt", "bad.txt", "c.txt")
	sc := &fakeScanner{gate: make(chan struct{}, 10), entered: make(chan struct{}, 1)}
	g := newRig(t, bundle(customSchedule(dir)), sc)
	before := runtime.NumGoroutine()
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	cur := g.r.Current()
	sc.gate <- struct{}{} // a.txt
	<-sc.entered
	<-sc.entered // waiting at bad.txt
	stopped := make(chan struct{})
	go func() { g.r.Stop(5 * time.Second); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung")
	}
	if g.r.Current() != nil {
		t.Fatal("scan still running after Stop")
	}
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); !errors.Is(err, ErrStopped) {
		t.Fatalf("start after stop: %v", err)
	}
	if err := g.r.Tick(); err != nil || g.r.Current() != nil {
		t.Fatal("tick started a scan after Stop")
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines %d > %d before the scan", n, before)
	}
	if len(g.q.summaries()) != 0 {
		t.Fatal("a stopped scheduled scan sent a summary")
	}

	// Restart.
	for range 4 {
		sc.gate <- struct{}{}
	}
	g.r = g.runner("")
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	s := g.waitEnd(t)
	if s.ScanID != cur.ScanID || s.State != yara.ScanCompleted || s.FilesScanned != 3 || s.Matches != 1 {
		t.Fatalf("resumed summary %+v", s)
	}
	sc.mu.Lock()
	got := strings.Join(sc.scanned, ",")
	sc.mu.Unlock()
	if got != "a.txt,bad.txt,c.txt" {
		t.Errorf("files scanned %s; each once, the interrupted one again", got)
	}
}

// A later scheduled scan skips unchanged files (skip cache) and doesn't
// report the same match again (dedupe is the store's; here the cache).
func TestScheduled_SkipCache(t *testing.T) {
	dir := files(t, "a.txt", "bad.txt")
	g := newRig(t, bundle(customSchedule(dir)), &fakeScanner{})
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	if s := g.waitEnd(t); s.FilesScanned != 2 {
		t.Fatalf("first %+v", s)
	}
	waitIdle(t, g.r)
	g.advance(25 * time.Hour)
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	s := g.waitEnd(t)
	if s.FilesScanned != 0 || s.FilesSkipped != 2 || s.State != yara.ScanCompleted {
		t.Fatalf("second %+v", s)
	}
}

// A schedule with no folders on this OS (custom) never starts a scan.
func TestScheduled_NothingOnThisOS(t *testing.T) {
	s := yara.Schedule{ID: schedA, Preset: yara.PresetCustom, EveryHours: 1}
	g := newRig(t, bundle(s), &fakeScanner{})
	if err := g.r.Tick(); err != nil || g.r.Current() != nil {
		t.Fatalf("started: %v", err)
	}
	st, err := loadState(g.state)
	if err != nil || st.Schedules[schedA] == nil || st.Schedules[schedA].LastRun.IsZero() {
		t.Fatalf("state %+v, %v", st, err)
	}
}

// Threat hunting turned off stops the scan (cancelled).
func TestDisable_CancelsScan(t *testing.T) {
	dir := files(t, "a.txt")
	sc := &fakeScanner{gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	g := newRig(t, bundle(customSchedule(dir)), sc)
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	<-sc.entered
	g.r.Disable()
	if s := g.waitEnd(t); s.State != yara.ScanCancelled || s.Trigger != yara.TriggerScheduled {
		t.Fatalf("summary %+v", s)
	}
	st, _ := loadState(g.state)
	if ss := st.Schedules[schedA]; ss == nil || ss.LastRun.IsZero() || ss.Resume != nil {
		t.Fatalf("schedule state %+v", ss)
	}
}

// A worker that keeps failing ends the scan as failed.
func TestScan_WorkersDown(t *testing.T) {
	names := make([]string, maxWorkerFailures+2)
	for i := range names {
		names[i] = string(rune('a'+i)) + ".txt"
	}
	dir := files(t, names...)
	g := newRig(t, bundle(), failingScanner{})
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	if s := g.waitEnd(t); s.State != yara.ScanFailed || s.Errors != maxWorkerFailures {
		t.Fatalf("summary %+v", s)
	}
}

type failingScanner struct{}

func (failingScanner) ScanFile(context.Context, ruleset.Rules, walk.File, []string, time.Duration) FileOutcome {
	return FileOutcome{Status: WorkerFailed}
}

// Hashed path mode: no path leaves the device.
func TestScan_HashedPaths(t *testing.T) {
	dir := files(t, "bad.exe")
	a := bundle()
	a.Bundle.Evidence.PathMode = yara.PathModeHashed
	g := newRig(t, a, &fakeScanner{})
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	g.waitEnd(t)
	ms := g.q.matches()
	if len(ms) != 1 || ms[0].Path != nil || ms[0].PathHash == nil || ms[0].FileExt != "exe" {
		t.Fatalf("match %+v", ms)
	}
	if *ms[0].PathHash != report.HashPath(filepath.Join(dir, "bad.exe")) {
		t.Error("path hash mismatch")
	}
}
