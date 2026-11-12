package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/walk"
)

// fakeWatch records the watches on-write starts.
type fakeWatch struct {
	mu      sync.Mutex
	started [][]string
	open    int
	err     error
	changed func(string)
	gone    func(string)
}

type fakeWatcher struct{ f *fakeWatch }

func (w fakeWatcher) Close() {
	w.f.mu.Lock()
	w.f.open--
	w.f.mu.Unlock()
}

func (f *fakeWatch) start(roots []string, changed func(string), _ func(), gone func(string)) (Watcher, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.started = append(f.started, roots)
	f.open++
	f.changed, f.gone = changed, gone
	return fakeWatcher{f}, nil
}

func (f *fakeWatch) state() (starts, open int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.started), f.open
}

// countGuard counts the files that waited on the CPU budget.
type countGuard struct{ n atomic.Int64 }

func (g *countGuard) Wait(context.Context) error { g.n.Add(1); return nil }

func onWriteBundle(dirs ...string) *ruleset.Active {
	a := bundle()
	ow := &yara.OnWrite{Enabled: true}
	switch runtime.GOOS {
	case "windows":
		ow.Paths.Windows = dirs
	case "darwin":
		ow.Paths.Darwin = dirs
	default:
		ow.Paths.Linux = dirs
	}
	a.Bundle.OnWrite = ow
	return a
}

type owRig struct {
	*rig
	ow    *OnWrite
	watch *fakeWatch
	guard *countGuard
}

func newOWRig(t *testing.T, a *ruleset.Active, sc FileScanner, o OnWriteOptions) *owRig {
	t.Helper()
	g := &owRig{rig: newRig(t, a, sc), watch: &fakeWatch{}, guard: &countGuard{}}
	o.Watch = g.watch.start
	if o.Tick == 0 {
		o.Tick = time.Hour // the tests flush by hand
	}
	o.NewGuard = func(yara.Limits, func() time.Duration) walk.Guard { return g.guard }
	g.ow = NewOnWrite(g.r, o)
	t.Cleanup(g.ow.Stop)
	return g
}

// drain flushes until nothing waits and the worker has emptied the queue.
func (g *owRig) drain(t *testing.T, at time.Time) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		g.ow.flush(at)
		g.ow.mu.Lock()
		left := len(g.ow.pending)
		g.ow.mu.Unlock()
		if left == 0 && len(g.ow.queue) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d files still waiting", left)
		}
		time.Sleep(time.Millisecond)
	}
}

// countScanner scans nothing: it records each file, so a burst test
// measures the pipeline rather than the disk.
type countScanner struct {
	mu   sync.Mutex
	seen map[string]int
}

func (s *countScanner) ScanFile(_ context.Context, _ ruleset.Rules, f walk.File, _ []string, _ time.Duration) FileOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]int{}
	}
	s.seen[f.Path]++
	return FileOutcome{Status: Scanned, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
}

func (s *countScanner) counts() (files, scans int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.seen {
		scans += n
	}
	return len(s.seen), scans
}

func (s *fakeScanner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.scanned)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestOnWrite_DebounceScanAndWindow(t *testing.T) {
	dir := files(t, "bad.bin", "good.txt")
	sc := &fakeScanner{}
	g := newOWRig(t, onWriteBundle(dir), sc, OnWriteOptions{})
	g.ow.Apply(g.active)
	if starts, open := g.watch.state(); starts != 1 || open != 1 {
		t.Fatalf("watch starts %d open %d", starts, open)
	}
	t0 := g.now
	bad, good := filepath.Join(dir, "bad.bin"), filepath.Join(dir, "good.txt")
	g.watch.changed(bad)
	g.watch.changed(good)
	g.advance(1500 * time.Millisecond)
	g.watch.changed(good) // still being written

	g.ow.flush(t0.Add(DefaultOnWriteQuiet)) // bad.bin quiet for 2 s, good.txt for 0.5 s
	waitFor(t, "bad.bin scanned", func() bool { return sc.count() == 1 })
	if sc.scanned[0] != "bad.bin" {
		t.Fatalf("scanned %v", sc.scanned)
	}
	g.drain(t, t0.Add(4*time.Second))
	waitFor(t, "good.txt scanned", func() bool { return sc.count() == 2 })

	ms := g.q.matches()
	if len(ms) != 1 || ms[0].Trigger != yara.TriggerOnWrite || ms[0].Rule != "test_marker" {
		t.Fatalf("matches %+v", ms)
	}
	st := g.ow.Status()
	if st == nil || st.Watching != 1 || st.Window == nil || st.Window.Scanned != 2 || st.Window.Matches != 1 ||
		st.Window.ScanID != ms[0].ScanID {
		t.Fatalf("status %+v window %+v", st, st.Window)
	}
	if g.guard.n.Load() != 2 {
		t.Errorf("CPU budget consulted for %d files, want 2", g.guard.n.Load())
	}

	// The window ends after 24 h with one on-write summary.
	g.ow.windowDue(g.now.Add(DefaultOnWriteWindow))
	sums := g.q.summaries()
	if len(sums) != 1 {
		t.Fatalf("%d summaries", len(sums))
	}
	s := sums[0]
	if s.ScanID != ms[0].ScanID || s.Trigger != yara.TriggerOnWrite || s.Preset != yara.PresetCustom ||
		s.State != yara.ScanCompleted || s.FilesScanned != 2 || s.Matches != 1 {
		t.Fatalf("summary %+v", s)
	}
	if g.ow.Status().Window != nil {
		t.Error("window still open")
	}
	// The status's last scan isn't an on-write window.
	if g.r.LastScan() != nil {
		t.Error("on-write window recorded as the last scan")
	}
}

// Unchanged files aren't scanned twice (skip cache); files outside the
// roots, excluded or gone are ignored; an empty window sends no summary.
func TestOnWrite_SkipsAndFilters(t *testing.T) {
	dir := files(t, "a.txt", "excluded.txt")
	outside := files(t, "b.txt")
	a := onWriteBundle(dir)
	excl := filepath.Join(dir, "excluded.txt")
	switch runtime.GOOS {
	case "windows":
		a.Bundle.OnWrite.Exclusions.Windows = []string{excl}
	case "darwin":
		a.Bundle.OnWrite.Exclusions.Darwin = []string{excl}
	default:
		a.Bundle.OnWrite.Exclusions.Linux = []string{excl}
	}
	sc := &fakeScanner{}
	g := newOWRig(t, a, sc, OnWriteOptions{})
	g.ow.Apply(a)
	g.watch.changed(filepath.Join(outside, "b.txt"))
	g.watch.changed(excl)
	if st := g.ow.Status(); st.Pending != 0 {
		t.Fatalf("%d pending, want 0", st.Pending)
	}
	g.watch.changed(filepath.Join(dir, "gone.tmp"))
	g.drain(t, g.now.Add(time.Minute))
	if g.ow.Status().Window != nil {
		t.Fatal("a vanished temp file opened a window")
	}

	p := filepath.Join(dir, "a.txt")
	g.watch.changed(p)
	g.drain(t, g.now.Add(time.Minute))
	waitFor(t, "a.txt scanned", func() bool { return sc.count() == 1 })
	g.watch.changed(p) // touched, not changed
	g.drain(t, g.now.Add(2*time.Minute))
	waitFor(t, "a.txt skipped", func() bool {
		w := g.ow.Status().Window
		return w != nil && w.Skipped == 1
	})
	if sc.count() != 1 {
		t.Errorf("unchanged file scanned again: %v", sc.scanned)
	}
}

// A file that never goes quiet is scanned MaxDelay after its first event.
func TestOnWrite_MaxDelay(t *testing.T) {
	dir := files(t, "log.txt")
	sc := &fakeScanner{}
	g := newOWRig(t, onWriteBundle(dir), sc, OnWriteOptions{})
	g.ow.Apply(g.active)
	p := filepath.Join(dir, "log.txt")
	t0 := g.now
	for i := range 59 {
		g.now = t0.Add(time.Duration(i) * time.Second)
		g.watch.changed(p)
		g.ow.flush(g.now.Add(time.Second))
	}
	if sc.count() != 0 || g.ow.Status().Pending != 1 {
		t.Fatal("a file still being written was scanned")
	}
	g.ow.flush(t0.Add(DefaultOnWriteMaxDelay))
	waitFor(t, "log.txt scanned", func() bool { return sc.count() == 1 })
}

// A burst (an archive unpacked into Downloads) is scanned once per file,
// within the CPU budget, with bounded memory: past MaxPending waiting
// files new ones are dropped and counted.
func TestOnWrite_Burst10k(t *testing.T) {
	if testing.Short() {
		t.Skip("creates 10,000 files")
	}
	const n = 10_000
	dir := t.TempDir()
	paths := make([]string, n)
	for i := range n {
		paths[i] = filepath.Join(dir, fmt.Sprintf("f%05d.txt", i))
		if err := os.WriteFile(paths[i], []byte(fmt.Sprintf("file %d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("all scanned once", func(t *testing.T) {
		sc := &countScanner{}
		g := newOWRig(t, onWriteBundle(dir), sc, OnWriteOptions{})
		g.ow.Apply(g.active)
		for range 3 { // each file reported several times while written
			for _, p := range paths {
				g.watch.changed(p)
			}
		}
		if st := g.ow.Status(); st.Pending != n || st.Dropped != 0 {
			t.Fatalf("pending %d dropped %d", st.Pending, st.Dropped)
		}
		g.drain(t, g.now.Add(time.Minute))
		waitFor(t, "every file scanned", func() bool { files, _ := sc.counts(); return files == n })
		time.Sleep(20 * time.Millisecond)
		if files, scans := sc.counts(); files != n || scans != n {
			t.Fatalf("scanned %d files %d times; want each of %d once", files, scans, n)
		}
		if g.guard.n.Load() != n {
			t.Errorf("CPU budget consulted %d times, want %d", g.guard.n.Load(), n)
		}
	})

	t.Run("capped", func(t *testing.T) {
		sc := &countScanner{}
		g := newOWRig(t, onWriteBundle(dir), sc, OnWriteOptions{MaxPending: 4096, QueueSize: 64})
		g.ow.Apply(g.active)
		for _, p := range paths {
			g.watch.changed(p)
		}
		st := g.ow.Status()
		if st.Pending != 4096 || st.Dropped != n-4096 {
			t.Fatalf("pending %d dropped %d", st.Pending, st.Dropped)
		}
		g.drain(t, g.now.Add(time.Minute))
		waitFor(t, "kept files scanned", func() bool { files, _ := sc.counts(); return files == 4096 })
	})
}

func TestOnWrite_Lifecycle(t *testing.T) {
	dir := files(t, "a.txt")
	other := files(t, "b.txt")
	sc := &fakeScanner{}
	g := newOWRig(t, bundle(), sc, OnWriteOptions{})

	g.ow.Apply(bundle()) // no on_write: nothing watched
	if starts, _ := g.watch.state(); starts != 0 || g.ow.Status() != nil {
		t.Fatal("watching without on_write")
	}
	a := onWriteBundle(dir)
	g.ow.Apply(a)
	g.ow.Apply(a) // unchanged: no restart
	if starts, open := g.watch.state(); starts != 1 || open != 1 {
		t.Fatalf("starts %d open %d", starts, open)
	}
	g.watch.gone(dir) // the folder went away: restarted on the next Apply
	g.ow.Apply(a)
	if starts, open := g.watch.state(); starts != 2 || open != 1 {
		t.Fatalf("after gone: starts %d open %d", starts, open)
	}
	b := onWriteBundle(dir, other) // new folders: restart
	g.ow.Apply(b)
	if starts, open := g.watch.state(); starts != 3 || open != 1 || len(g.watch.started[2]) != 2 {
		t.Fatalf("new roots: starts %d open %d %v", starts, open, g.watch.started)
	}

	g.watch.changed(filepath.Join(dir, "a.txt"))
	off := onWriteBundle(dir)
	off.Bundle.OnWrite.Enabled = false
	g.ow.Apply(off) // turned off: watch closed, waiting files dropped
	if _, open := g.watch.state(); open != 0 {
		t.Fatal("watch still open after on_write was turned off")
	}
	if st := g.ow.Status(); st != nil {
		t.Fatalf("status %+v after off", st)
	}

	disabled := onWriteBundle(dir)
	disabled.Rules = nil // threat hunting off
	g.ow.Apply(disabled)
	if _, open := g.watch.state(); open != 0 {
		t.Fatal("watching with threat hunting off")
	}

	g.ow.Apply(a)
	g.ow.Stop()
	g.ow.Apply(a) // after Stop nothing starts
	if _, open := g.watch.state(); open != 0 {
		t.Fatal("watch open after Stop")
	}
}

// A watcher that can't start is retried on the next Apply and reported.
func TestOnWrite_WatchError(t *testing.T) {
	dir := files(t, "a.txt")
	g := newOWRig(t, onWriteBundle(dir), &fakeScanner{}, OnWriteOptions{})
	g.watch.err = fmt.Errorf("fanotify: operation not permitted")
	g.ow.Apply(g.active)
	if st := g.ow.Status(); st == nil || st.Watching != 0 || st.Error == "" {
		t.Fatalf("status %+v", st)
	}
	g.watch.mu.Lock()
	g.watch.err = nil
	g.watch.mu.Unlock()
	g.ow.Apply(g.active)
	if st := g.ow.Status(); st.Watching != 1 || st.Error != "" {
		t.Fatalf("status after retry %+v", st)
	}
}

// Stop ends the window: its summary is queued.
func TestOnWrite_StopSendsSummary(t *testing.T) {
	dir := files(t, "a.txt")
	sc := &fakeScanner{}
	g := newOWRig(t, onWriteBundle(dir), sc, OnWriteOptions{})
	g.ow.Apply(g.active)
	g.watch.changed(filepath.Join(dir, "a.txt"))
	g.drain(t, g.now.Add(time.Minute))
	waitFor(t, "a.txt scanned", func() bool { return sc.count() == 1 })
	waitFor(t, "window counted", func() bool {
		w := g.ow.Status().Window
		return w != nil && w.Scanned == 1
	})
	g.ow.Stop()
	if s := g.q.summaries(); len(s) != 1 || s[0].Trigger != yara.TriggerOnWrite || s[0].FilesScanned != 1 {
		t.Fatalf("summaries %+v", s)
	}
}

// slowScanner takes d per file, standing in for a worker busy on the CPU.
type slowScanner struct {
	countScanner
	d time.Duration
}

func (s *slowScanner) ScanFile(ctx context.Context, r ruleset.Rules, f walk.File, ids []string, t time.Duration) FileOutcome {
	time.Sleep(s.d)
	return s.countScanner.ScanFile(ctx, r, f, ids, t)
}

// The default guard holds on-write scans to the bundle's CPU budget: at
// 25% of a core, 20 files of 20 ms each take at least ~4x their scan time.
func TestOnWrite_CPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	names := make([]string, 20)
	for i := range names {
		names[i] = fmt.Sprintf("f%02d.txt", i)
	}
	dir := files(t, names...)
	a := onWriteBundle(dir)
	a.Bundle.Limits.MaxCPUPercent = 25
	a.Bundle.Limits.SkipOnBattery = true // ignored by on-write
	sc := &slowScanner{d: 20 * time.Millisecond}
	g := &owRig{rig: newRig(t, a, sc), watch: &fakeWatch{}}
	g.r.o.OnBattery = func() bool { return true }
	g.ow = NewOnWrite(g.r, OnWriteOptions{Watch: g.watch.start, Tick: time.Hour})
	t.Cleanup(g.ow.Stop)
	g.ow.Apply(a)
	for _, n := range names {
		g.watch.changed(filepath.Join(dir, n))
	}
	start := time.Now()
	g.drain(t, g.now.Add(time.Minute))
	waitFor(t, "all files scanned", func() bool { files, _ := sc.counts(); return files == len(names) })
	busy := time.Duration(len(names)) * sc.d
	if took := time.Since(start); took < 3*busy {
		t.Fatalf("20 files took %v with %v of scanning: CPU budget not applied", took, busy)
	}
}
