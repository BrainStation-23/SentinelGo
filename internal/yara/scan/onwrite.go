package scan

// On-write scanning (#418, contract v1.1): files written or renamed into
// watched folders are scanned once they have been quiet for a moment, so a
// dropped tool is found in seconds instead of at the next scheduled scan.
//
//	watcher ──Changed──► pending (debounce, capped) ──► queue (capped) ──► worker
//
// The watcher's callbacks only record a path; nothing waits on a scan. A
// file is handed on once it has been quiet for Quiet (or, when it keeps
// changing, MaxDelay after its first event). Past MaxPending distinct files
// waiting, new ones are dropped and counted: the next scheduled scan
// finds them. The worker scans through the Runner's gate (below on-demand,
// above scheduled scans), within the bundle's CPU budget, with the skip
// cache and the same per-file checks as a walk.
//
// Matches are reported like a scheduled scan's (de-duplicated), under a
// window's scan id: a window lasts up to Window and ends with one
// scan_summary (trigger on_write) when anything was scanned in it.

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/report"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/walk"
)

// On-write defaults.
const (
	DefaultOnWriteQuiet      = 2 * time.Second
	DefaultOnWriteMaxDelay   = time.Minute
	DefaultOnWriteMaxPending = 16384
	DefaultOnWriteQueue      = 1024
	DefaultOnWriteWindow     = 24 * time.Hour
)

// onWritePreset labels on-write summaries (contract v1.1): a folder list.
const onWritePreset = yara.PresetCustom

// Watcher is a running file system watch (watch.Watcher).
type Watcher interface{ Close() }

// WatchFunc starts watching roots (watch.Start): changed gets each file
// written or renamed into place, lost is called when notifications were
// dropped and gone when a root went away. It returns a Watcher when at
// least one root is watched.
type WatchFunc func(roots []string, changed func(path string), lost func(), gone func(root string)) (Watcher, error)

// OnWriteOptions configure on-write scanning.
type OnWriteOptions struct {
	Watch WatchFunc
	// Zero values take the defaults above.
	Quiet      time.Duration
	MaxDelay   time.Duration
	MaxPending int
	QueueSize  int
	Window     time.Duration
	// Tick is how often waiting files are checked (default Quiet/8).
	Tick time.Duration
	// NewGuard returns the CPU budget each file waits on (tests);
	// default walk.NewThrottle without the per-scan limits.
	NewGuard func(limits yara.Limits, cpuTime func() time.Duration) walk.Guard
}

// OnWriteStatus is on-write scanning's state for `sentinelgo yara status`.
type OnWriteStatus struct {
	// Watching is the number of folders watched (0: off).
	Watching int    `json:"watching"`
	Error    string `json:"error,omitempty"`
	Pending  int    `json:"pending"`
	// Dropped files weren't scanned because too many were waiting; Lost
	// counts the times the OS dropped notifications.
	Dropped uint64 `json:"dropped"`
	Lost    uint64 `json:"lost"`
	// Window is the current reporting window (nil before the first file).
	Window *OnWriteWindow `json:"window,omitempty"`
}

// OnWriteWindow is the current window's counts.
type OnWriteWindow struct {
	ScanID  string    `json:"scan_id"`
	Started time.Time `json:"started"`
	Scanned int64     `json:"scanned"`
	Skipped int64     `json:"skipped"`
	Errors  int64     `json:"errors"`
	Matches int64     `json:"matches"`
}

// OnWrite runs on-write scanning next to a Runner.
type OnWrite struct {
	r *Runner
	o OnWriteOptions

	applyMu sync.Mutex // one Apply at a time
	mu      sync.Mutex
	cfg     *owConfig // nil: off
	w       Watcher
	roots   []string // what w watches
	werr    string
	regone  bool // a root went away: restart the watch
	pending map[string]owPending
	stopped bool

	queue  chan string
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dropped, lost atomic.Uint64

	winMu sync.Mutex
	win   *owWindow
}

// owConfig is what on-write scanning runs with, from one bundle.
type owConfig struct {
	active   *ruleset.Active
	roots    []string
	walk     walk.Options // per-file checks (Cache and Guard unset)
	ids      []string
	rulesKey string
	timeout  time.Duration
	guard    walk.Guard
}

type owPending struct{ first, last time.Time }

type owWindow struct {
	rep                      *report.Scan
	active                   *ruleset.Active
	opened                   time.Time
	scanned, skipped, errors int64
}

// NewOnWrite returns on-write scanning for r, off until Apply sees a bundle
// that enables it.
func NewOnWrite(r *Runner, o OnWriteOptions) *OnWrite {
	if o.Quiet <= 0 {
		o.Quiet = DefaultOnWriteQuiet
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = DefaultOnWriteMaxDelay
	}
	if o.MaxPending <= 0 {
		o.MaxPending = DefaultOnWriteMaxPending
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultOnWriteQueue
	}
	if o.Window <= 0 {
		o.Window = DefaultOnWriteWindow
	}
	if o.Tick <= 0 {
		o.Tick = o.Quiet / 8
	}
	if o.NewGuard == nil {
		o.NewGuard = func(l yara.Limits, cpu func() time.Duration) walk.Guard {
			// Only the CPU budget: on-write isn't a walk, so the file and
			// time limits don't apply, and a new file is worth a scan on
			// battery too.
			l.MaxFilesPerScan, l.MaxScanMinutes, l.SkipOnBattery = 0, 0, false
			return walk.NewThrottle(l, nil, cpu)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ow := &OnWrite{r: r, o: o, pending: map[string]owPending{}, queue: make(chan string, o.QueueSize),
		ctx: ctx, cancel: cancel}
	ow.wg.Add(2)
	go ow.tickLoop()
	go ow.scanLoop()
	return ow
}

// Apply follows the bundle in force (the ruleset sync's OnChange, and
// periodically, so new user folders and drives are picked up): it starts,
// restarts or stops the watch.
func (ow *OnWrite) Apply(a *ruleset.Active) {
	ow.applyMu.Lock()
	defer ow.applyMu.Unlock()
	cfg := ow.config(a)
	ow.mu.Lock()
	if ow.stopped {
		ow.mu.Unlock()
		return
	}
	prev := ow.cfg
	ow.cfg = cfg
	var closeW Watcher
	switch {
	case cfg == nil:
		closeW, ow.w, ow.roots, ow.werr, ow.regone = ow.w, nil, nil, "", false
		clear(ow.pending)
	case ow.w == nil || ow.regone || !slices.Equal(cfg.roots, ow.roots):
		closeW, ow.w, ow.roots, ow.regone = ow.w, nil, nil, false
	}
	needStart := cfg != nil && ow.w == nil
	ow.mu.Unlock()
	if closeW != nil {
		closeW.Close()
	}
	if prev != nil && (cfg == nil || cfg.active != prev.active) {
		ow.closeWindow() // new rules or evidence mode: new window
	}
	if needStart {
		ow.startWatch(cfg)
	}
}

// config derives the on-write configuration from a; nil when on-write is
// off (no enabled bundle, on_write off, nothing to watch on this device).
func (ow *OnWrite) config(a *ruleset.Active) *owConfig {
	if !a.Enabled() || !a.Bundle.OnWriteEnabled() {
		return nil
	}
	env := ow.r.o.Env
	b := a.Bundle
	roots := walk.OnWriteRoots(b.OnWrite.Paths.For(env.GOOS), env)
	if len(roots) == 0 {
		return nil
	}
	ids := b.OnWrite.RulesetIDs
	if ids != nil && len(b.RulesetsFor(ids)) == 0 {
		return nil
	}
	l := b.Limits
	return &owConfig{
		active: a, roots: roots, ids: ids, rulesKey: rulesKey(a, ids),
		timeout: time.Duration(l.PerFileTimeoutMS) * time.Millisecond,
		walk: walk.Options{GOOS: env.GOOS, Exclude: walk.NewExcluder(b.OnWrite.Exclusions.For(env.GOOS), ow.r.o.ExcludeDir, env),
			MaxFileBytes: l.MaxFileBytes, Mounts: ow.r.o.Mounts(),
			IncludeNetwork: l.IncludeNetworkMounts, IncludeRemovable: l.IncludeRemovable},
		guard: ow.o.NewGuard(l, func() time.Duration { return time.Duration(ow.r.busy.Load()) }),
	}
}

func (ow *OnWrite) startWatch(cfg *owConfig) {
	w, err := ow.o.Watch(cfg.roots, ow.changed, ow.lostEvents, ow.rootGone)
	ow.mu.Lock()
	defer ow.mu.Unlock()
	if ow.stopped || ow.cfg != cfg {
		if w != nil {
			go w.Close() // Apply raced us; not under ow.mu (callbacks take it)
		}
		return
	}
	ow.werr = ""
	if err != nil {
		ow.werr = yara.Truncate(err.Error(), yara.MaxErrorLen)
		log.Printf("YARA: on-write: %v", err)
	}
	if w == nil {
		return // retried on the next Apply
	}
	ow.w, ow.roots = w, cfg.roots
	log.Printf("YARA: on-write scanning started (%d folders)", len(cfg.roots))
}

// changed is the watcher's callback: record the path, nothing else.
func (ow *OnWrite) changed(path string) {
	now := ow.r.o.Now()
	ow.mu.Lock()
	defer ow.mu.Unlock()
	cfg := ow.cfg
	if cfg == nil {
		return
	}
	if _, ok := walk.Under(path, cfg.roots, cfg.walk.GOOS); !ok || walk.Excluded(cfg.walk, path) {
		return
	}
	if p, ok := ow.pending[path]; ok {
		p.last = now
		ow.pending[path] = p
		return
	}
	if len(ow.pending) >= ow.o.MaxPending {
		ow.dropped.Add(1)
		return
	}
	ow.pending[path] = owPending{first: now, last: now}
}

func (ow *OnWrite) lostEvents() { ow.lost.Add(1) }

func (ow *OnWrite) rootGone(string) {
	ow.mu.Lock()
	ow.regone = true
	ow.mu.Unlock()
}

// tickLoop hands quiet files to the worker and ends windows.
func (ow *OnWrite) tickLoop() {
	defer ow.wg.Done()
	t := time.NewTicker(ow.o.Tick)
	defer t.Stop()
	for {
		select {
		case <-ow.ctx.Done():
			return
		case <-t.C:
			now := ow.r.o.Now()
			ow.flush(now)
			ow.windowDue(now)
		}
	}
}

// flush queues the files that have been quiet long enough, or have waited
// MaxDelay. A full queue leaves them waiting (they stay counted against
// MaxPending).
func (ow *OnWrite) flush(now time.Time) {
	ow.mu.Lock()
	defer ow.mu.Unlock()
	for path, p := range ow.pending {
		if now.Sub(p.last) < ow.o.Quiet && now.Sub(p.first) < ow.o.MaxDelay {
			continue
		}
		select {
		case ow.queue <- path:
			delete(ow.pending, path)
		default:
			return
		}
	}
}

func (ow *OnWrite) scanLoop() {
	defer ow.wg.Done()
	for {
		select {
		case <-ow.ctx.Done():
			return
		case path := <-ow.queue:
			ow.scan(path)
		}
	}
}

// scan checks and scans one file and reports its matches.
func (ow *OnWrite) scan(path string) {
	ow.mu.Lock()
	cfg := ow.cfg
	ow.mu.Unlock()
	if cfg == nil {
		return
	}
	ctx := ow.ctx
	o := cfg.walk
	o.Cache, o.Rules = ow.r.skipCache(), cfg.rulesKey
	f, reason, err := walk.Stat(o, path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return // a temp file, gone again: nothing reached the disk to scan
	case err != nil:
		ow.count(cfg, func(w *owWindow) { w.errors++ })
		return
	case reason != "":
		ow.count(cfg, func(w *owWindow) { w.skipped++ })
		return
	}
	if err := cfg.guard.Wait(ctx); err != nil {
		return
	}
	out, err := ow.r.scanOne(ctx, prioOnWrite, cfg.active.Rules, f, cfg.ids, cfg.timeout)
	if err != nil {
		return
	}
	switch out.Status {
	case Scanned:
	case Skipped:
		ow.count(cfg, func(w *owWindow) { w.skipped++ })
		return
	default: // read error, worker failure, no rules
		ow.count(cfg, func(w *owWindow) { w.errors++ })
		return
	}
	result := walk.Clean
	var queueErr error
	ow.count(cfg, func(w *owWindow) {
		w.scanned++
		if len(out.Matches) == 0 {
			return
		}
		result = walk.Matched
		evs, err := w.rep.Matches(report.FileResult{Path: f.Path, SHA256: out.SHA256, Size: out.Size,
			MTime: time.Unix(0, f.Key.MTime), Hits: hits(cfg.active, out.Matches)})
		if err == nil && len(evs) > 0 {
			err = ow.r.o.Queue.Add(evs)
		}
		if err != nil {
			w.errors++
			queueErr = err
		}
	})
	if queueErr != nil {
		log.Printf("YARA: on-write: match events not queued: %v", queueErr)
		return // not cached: the next scan reports it again
	}
	if o.Cache != nil {
		o.Cache.Store(f.Key, cfg.rulesKey, result)
	}
}

// count updates the current window, opening one for cfg's bundle if needed.
func (ow *OnWrite) count(cfg *owConfig, fn func(w *owWindow)) {
	ow.winMu.Lock()
	defer ow.winMu.Unlock()
	if ow.win == nil {
		ow.win = &owWindow{active: cfg.active, opened: ow.r.o.Now(),
			rep: report.NewScan("", yara.TriggerOnWrite, onWritePreset, cfg.active.Bundle.Evidence, ow.r.o.Dedupe)}
	}
	fn(ow.win)
}

// windowDue ends the window once it is Window old.
func (ow *OnWrite) windowDue(now time.Time) {
	ow.winMu.Lock()
	due := ow.win != nil && now.Sub(ow.win.opened) >= ow.o.Window
	ow.winMu.Unlock()
	if due {
		ow.closeWindow()
	}
}

// closeWindow sends the window's scan_summary (when anything was scanned,
// skipped or failed in it) and saves the skip cache.
func (ow *OnWrite) closeWindow() {
	ow.winMu.Lock()
	w := ow.win
	ow.win = nil
	ow.winMu.Unlock()
	if w == nil {
		return
	}
	if c := ow.r.skipCache(); c != nil {
		if err := c.Save(); err != nil {
			log.Printf("YARA: %v", err)
		}
	}
	if w.scanned+w.skipped+w.errors == 0 {
		return
	}
	sum := w.rep.Summary(yara.ScanCompleted, w.scanned, w.skipped, w.errors)
	if err := ow.r.o.Queue.Add([]yara.Event{sum}); err != nil {
		log.Printf("YARA: could not queue the summary of on-write window %s: %v", w.rep.ID, err)
	}
	log.Printf("YARA: on-write window %s ended: %d files scanned, %d skipped, %d errors, %d matches",
		w.rep.ID, w.scanned, w.skipped, w.errors, sum.Summary.Matches)
}

// Status returns on-write scanning's state.
func (ow *OnWrite) Status() *OnWriteStatus {
	ow.mu.Lock()
	st := &OnWriteStatus{Watching: len(ow.roots), Error: ow.werr, Pending: len(ow.pending),
		Dropped: ow.dropped.Load(), Lost: ow.lost.Load()}
	on := ow.cfg != nil
	ow.mu.Unlock()
	if !on && st.Dropped == 0 && st.Lost == 0 {
		return nil
	}
	ow.winMu.Lock()
	if w := ow.win; w != nil {
		st.Window = &OnWriteWindow{ScanID: w.rep.ID, Started: w.rep.Started, Scanned: w.scanned,
			Skipped: w.skipped, Errors: w.errors, Matches: w.rep.Progress().Found}
	}
	ow.winMu.Unlock()
	return st
}

// Stop ends on-write scanning: the watch, the worker (a file being scanned
// is abandoned) and the window, whose summary is queued. Files still
// waiting are dropped; the next scheduled scan covers them.
func (ow *OnWrite) Stop() {
	ow.mu.Lock()
	if ow.stopped {
		ow.mu.Unlock()
		return
	}
	ow.stopped = true
	w := ow.w
	ow.w, ow.cfg = nil, nil
	ow.mu.Unlock()
	if w != nil {
		w.Close()
	}
	ow.cancel()
	ow.wg.Wait()
	ow.closeWindow()
}
