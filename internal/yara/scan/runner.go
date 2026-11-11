// Package scan runs threat hunting (YARA) scans (#414): the bundle's
// schedules, with a stable per-device start offset, and on-demand scans from
// the yara-scan native task. One scan runs at a time; an on-demand scan
// preempts a scheduled one, which resumes from its checkpoint afterwards. A
// scan the service stops is checkpointed and resumes after the restart if
// its schedule is still due.
//
// A scan lists files (walk), has a sandboxed worker read each one
// (FileScanner), turns matches into §3 events (report) and queues them for
// upload. Nothing here reads file content or logs rule text, matched bytes
// or file paths.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
	"sentinelgo/internal/yara/report"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/walk"
)

// Errors StartOnDemand returns; the yara-scan task fails with them and no
// scan starts.
var (
	ErrDisabled   = errors.New("threat hunting is off on this device (no enabled ruleset bundle, or yara_enabled is false)")
	ErrNoRulesets = errors.New("none of the requested rulesets is applied on this device")
	ErrNoPaths    = errors.New("nothing to scan: none of the scan's folders exists on this device")
	ErrStopped    = errors.New("the agent is stopping")
)

// Why a running scan was stopped (the context's cause).
var (
	errPreempted = errors.New("preempted by an on-demand scan")
	errShutdown  = errors.New("the service is stopping")
	errCancelled = errors.New("cancelled by yara-scan-cancel")
	errDisabled  = errors.New("threat hunting was turned off")
	errWorkers   = errors.New("no scan worker could scan files")
	errNoRules   = errors.New("the scan worker has no rules")
)

// maxWorkerFailures ends a scan as failed after this many files in a row
// that no worker could scan (the pool is disabled or keeps crashing).
const maxWorkerFailures = 10

// Outcome is how one file scan went (FileOutcome.Status).
type Outcome int

// Outcomes.
const (
	Scanned      Outcome = iota // read to the end and matched against the rules
	Skipped                     // per-file timeout, or the file changed since it was listed
	ReadError                   // couldn't be opened or read
	WorkerFailed                // no worker could scan it
	NoRules                     // the worker had no compiled rules
)

// FileOutcome is one file's result. SHA256 and Size come from the worker's
// read; Matches carry rule and string identifiers only.
type FileOutcome struct {
	Status  Outcome
	SHA256  string
	Size    int64
	Matches []engine.Match
}

// FileScanner opens a listed file and has a sandboxed worker scan it with
// rules (the Rules of ruleset.Active), limited to rulesetIDs (nil: all).
type FileScanner interface {
	ScanFile(ctx context.Context, rules ruleset.Rules, f walk.File, rulesetIDs []string, timeout time.Duration) FileOutcome
}

// Queue takes events for upload (store.YARAEventStore).
type Queue interface {
	Add(evs []yara.Event) error
}

// Options configure a Runner.
type Options struct {
	// Active returns the bundle in force (ruleset.Syncer.Active).
	Active  func() *ruleset.Active
	Scanner FileScanner
	Queue   Queue
	// Dedupe skips matches already reported, for scheduled scans.
	Dedupe report.Dedupe
	// AgentID seeds each schedule's start offset.
	AgentID string
	// StatePath and SkipCachePath are files next to config.json; "" keeps
	// nothing on disk.
	StatePath     string
	SkipCachePath string
	Env           walk.Env
	// Mounts lists removable drives and network shares right now.
	Mounts func() []walk.Mount
	// ExcludeDir is the agent's own folder, never scanned.
	ExcludeDir string
	// OnBattery reports whether the device runs on battery (nil: never).
	OnBattery func() bool
	// BeforeOnDemand runs when an on-demand scan starts: the ruleset sync
	// polls soon, in case the admin published rules with the request.
	BeforeOnDemand func()
	// OnScanEnd gets each finished scan's summary (also queued as a
	// scan_summary event) and whether macOS privacy refused folders.
	OnScanEnd func(sum *yara.ScanSummary, tccDenied bool)
	// Now is the clock (tests).
	Now func() time.Time
}

// Running describes the scan in progress.
type Running struct {
	ScanID     string    `json:"scan_id"`
	Trigger    string    `json:"trigger"`
	Preset     string    `json:"preset"`
	ScheduleID string    `json:"schedule_id,omitempty"`
	Started    time.Time `json:"started"`
	Files      int64     `json:"files"`
}

// Runner runs one scan at a time.
type Runner struct {
	o Options

	mu      sync.Mutex
	cur     *job
	stopped bool
	wg      sync.WaitGroup

	// stateMu serialises the state file's read-modify-write.
	stateMu sync.Mutex
	cache   *walk.Cache
	cacheMu sync.Mutex

	busy atomic.Int64 // nanoseconds spent in ScanFile: the workers' CPU budget
}

type job struct {
	spec    spec
	started time.Time
	cancel  context.CancelCauseFunc
	done    chan struct{}
	files   atomic.Int64
}

// spec is a scan to run.
type spec struct {
	ScanID     string
	Trigger    string
	Preset     string
	ScheduleID string
	Roots      []string
	Exclusions []string
	RulesetIDs []string // nil: all
	Active     *ruleset.Active
	RulesKey   string
	Resume     *resume
}

// New returns a Runner.
func New(o Options) *Runner {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Mounts == nil {
		o.Mounts = func() []walk.Mount { return nil }
	}
	return &Runner{o: o}
}

// Current returns the scan in progress, or nil.
func (r *Runner) Current() *Running {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil {
		return nil
	}
	s := r.cur.spec
	return &Running{ScanID: s.ScanID, Trigger: s.Trigger, Preset: s.Preset, ScheduleID: s.ScheduleID,
		Started: r.cur.started, Files: r.cur.files.Load()}
}

// Schedules returns the bundle's schedules with their last and next run on
// this device.
func (r *Runner) Schedules() []ScheduleStatus {
	a := r.o.Active()
	if !a.Enabled() {
		return nil
	}
	r.stateMu.Lock()
	st, _ := loadState(r.o.StatePath)
	r.stateMu.Unlock()
	out := make([]ScheduleStatus, 0, len(a.Bundle.Schedules))
	for _, s := range a.Bundle.Schedules {
		ss := ScheduleStatus{ID: s.ID, Preset: s.Preset, EveryHours: s.EveryHours}
		if x := st.Schedules[strings.ToLower(s.ID)]; x != nil {
			ss.LastRun, ss.Resumes = x.LastRun, x.Resume != nil
			ss.NextRun = NextRun(s, r.o.AgentID, x.Seen, x.LastRun)
		}
		out = append(out, ss)
	}
	return out
}

// LastScan returns the last finished scan from the state file.
func (r *Runner) LastScan() *yara.ScanSummary {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	st, _ := loadState(r.o.StatePath)
	return st.LastScan
}

// StartOnDemand starts the yara-scan task's scan and returns as soon as it
// runs: {scan_id, state: started}. A scheduled scan in progress is stopped
// first (it resumes later); another on-demand scan makes this one busy and
// it doesn't start. Invalid scopes are errors, and nothing starts.
func (r *Runner) StartOnDemand(p yara.TaskParams) (yara.TaskResult, error) {
	a := r.o.Active()
	if !a.Enabled() {
		return yara.TaskResult{}, ErrDisabled
	}
	ids := p.RulesetIDs
	if ids != nil {
		if len(a.Bundle.RulesetsFor(ids)) == 0 {
			return yara.TaskResult{}, ErrNoRulesets
		}
	}
	roots := walk.Roots(p.Preset, p.Paths, r.o.Env)
	if len(roots) == 0 {
		return yara.TaskResult{}, ErrNoPaths
	}
	id := p.ScanID
	if id == "" {
		id = yara.NewID()
	}
	sp := spec{ScanID: strings.ToLower(id), Trigger: yara.TriggerOnDemand, Preset: p.Preset, Roots: roots,
		RulesetIDs: ids, Active: a, RulesKey: rulesKey(a, ids)}

	r.mu.Lock()
	for {
		if r.stopped {
			r.mu.Unlock()
			return yara.TaskResult{}, ErrStopped
		}
		if r.cur == nil {
			break
		}
		if r.cur.spec.Trigger == yara.TriggerOnDemand {
			running := r.cur.spec.ScanID
			r.mu.Unlock()
			return yara.TaskResult{ScanID: sp.ScanID, State: yara.TaskBusy, RunningScanID: running}, nil
		}
		cur := r.cur
		log.Printf("YARA: on-demand scan %s preempts scheduled scan %s", sp.ScanID, cur.spec.ScanID)
		cur.cancel(errPreempted)
		r.mu.Unlock()
		<-cur.done
		r.mu.Lock()
	}
	r.startLocked(sp)
	r.mu.Unlock()
	if r.o.BeforeOnDemand != nil {
		r.o.BeforeOnDemand()
	}
	return yara.TaskResult{ScanID: sp.ScanID, State: yara.TaskStarted}, nil
}

// Cancel stops the running scan (yara-scan-cancel) and waits for it to end.
// It returns the scan's id, or "" when none was running.
func (r *Runner) Cancel() string {
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	if cur == nil {
		return ""
	}
	cur.cancel(errCancelled)
	<-cur.done
	return cur.spec.ScanID
}

// Disable stops the running scan because threat hunting was turned off
// (the ruleset sync's OnChange with a disabled bundle).
func (r *Runner) Disable() {
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	if cur != nil {
		cur.cancel(errDisabled)
		<-cur.done
	}
}

// Stop cancels the running scan and checkpoints it (a scheduled scan resumes
// after the restart), then waits up to timeout for it to end. No scan
// starts afterwards.
func (r *Runner) Stop(timeout time.Duration) {
	r.mu.Lock()
	r.stopped = true
	if r.cur != nil {
		r.cur.cancel(errShutdown)
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("Warning: YARA scan did not stop within %v", timeout)
	}
}

// Tick is the yara-scan-scheduler task: it starts the first due schedule
// unless a scan is running. Scans run in the background; Tick returns at
// once.
func (r *Runner) Tick() error {
	r.mu.Lock()
	busy := r.cur != nil || r.stopped
	r.mu.Unlock()
	if busy {
		return nil
	}
	a := r.o.Active()
	if !a.Enabled() {
		return nil
	}
	sp, ok, err := r.dueSchedule(a)
	if err != nil || !ok {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil || r.stopped {
		return nil // an on-demand scan got there first; retry next tick
	}
	r.startLocked(sp)
	return nil
}

// dueSchedule picks the schedule to run now: one with a stopped scan to
// continue first, then the bundle's order. It records schedules seen for the
// first time, forgets removed ones, and marks schedules with nothing to scan
// on this OS as run.
func (r *Runner) dueSchedule(a *ruleset.Active) (spec, bool, error) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	st, err := loadState(r.o.StatePath)
	if err != nil {
		log.Printf("YARA: %v", err)
	}
	now := r.o.Now().UTC()
	dirty := false
	inBundle := map[string]bool{}
	for _, s := range a.Bundle.Schedules {
		key := strings.ToLower(s.ID)
		inBundle[key] = true
		if st.Schedules[key] == nil {
			st.Schedules[key] = &schedState{Seen: now}
			dirty = true
		}
	}
	for id := range st.Schedules {
		if !inBundle[id] {
			delete(st.Schedules, id)
			dirty = true
		}
	}
	var pick *yara.Schedule
	for pass := 0; pass < 2 && pick == nil; pass++ {
		for i := range a.Bundle.Schedules {
			s := &a.Bundle.Schedules[i]
			ss := st.Schedules[strings.ToLower(s.ID)]
			if pass == 0 && (ss.Resume == nil || ss.Resume.Scan == nil) {
				continue
			}
			if now.Before(NextRun(*s, r.o.AgentID, ss.Seen, ss.LastRun)) {
				continue
			}
			roots := walk.Roots(s.Preset, s.Paths.For(r.o.Env.GOOS), r.o.Env)
			if len(roots) == 0 {
				ss.LastRun, ss.Resume, dirty = now, nil, true // nothing on this OS this period
				continue
			}
			pick = s
			break
		}
	}
	if dirty {
		if err := st.save(r.o.StatePath); err != nil {
			log.Printf("YARA: %v", err)
		}
	}
	if pick == nil {
		return spec{}, false, nil
	}
	ss := st.Schedules[strings.ToLower(pick.ID)]
	sp := spec{Trigger: yara.TriggerScheduled, Preset: pick.Preset, ScheduleID: strings.ToLower(pick.ID),
		Roots:      walk.Roots(pick.Preset, pick.Paths.For(r.o.Env.GOOS), r.o.Env),
		Exclusions: pick.Exclusions.For(r.o.Env.GOOS), RulesetIDs: pick.RulesetIDs, Active: a,
		RulesKey: rulesKey(a, pick.RulesetIDs)}
	if res := ss.Resume; res != nil && res.RulesKey == sp.RulesKey && res.Checkpoint.RootsKey == walk.RootsKey(sp.Roots) {
		sp.Resume = res
	}
	if sp.Resume != nil && sp.Resume.Scan != nil {
		sp.ScanID = sp.Resume.Scan.ScanID
	} else {
		sp.ScanID = yara.NewID()
	}
	return sp, true, nil
}

// startLocked runs sp in the background; r.mu is held.
func (r *Runner) startLocked(sp spec) {
	ctx, cancel := context.WithCancelCause(context.Background())
	j := &job{spec: sp, started: r.o.Now().UTC(), cancel: cancel, done: make(chan struct{})}
	if sp.Resume != nil && sp.Resume.Scan != nil {
		j.started = sp.Resume.Scan.Started
	}
	r.cur = j
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(j.done)
		defer cancel(nil)
		r.run(ctx, j)
		r.mu.Lock()
		if r.cur == j {
			r.cur = nil
		}
		r.mu.Unlock()
	}()
}

// counts are a scan's file counts.
type counts struct {
	scanned, skipped, errors int64
	workerFails              int
}

// run runs one scan to its end (or its interruption) and records it.
func (r *Runner) run(ctx context.Context, j *job) {
	sp := j.spec
	a := sp.Active
	b := a.Bundle
	rep := report.NewScan(sp.ScanID, sp.Trigger, sp.Preset, b.Evidence, r.o.Dedupe)
	var c counts
	tcc := false
	var resumeFrom *walk.Checkpoint
	if sp.Resume != nil {
		cp := sp.Resume.Checkpoint
		resumeFrom = &cp
		if in := sp.Resume.Scan; in != nil {
			rep.Restore(in.Started, in.Progress)
			c.scanned, c.skipped, c.errors, tcc = in.Scanned, in.Skipped, in.Errors, in.TCCDenied
		}
	}
	log.Printf("YARA: %s %s scan %s started (%d folders)", sp.Trigger, sp.Preset, sp.ScanID, len(sp.Roots))

	var cache *walk.Cache
	if sp.Trigger == yara.TriggerScheduled {
		cache = r.skipCache()
		if cache != nil {
			cache.BeginScan()
		}
	}
	limits := b.Limits
	timeout := time.Duration(limits.PerFileTimeoutMS) * time.Millisecond
	guard := walk.NewThrottle(limits, r.o.OnBattery, func() time.Duration { return time.Duration(r.busy.Load()) })
	o := walk.Options{
		GOOS: r.o.Env.GOOS, Roots: sp.Roots, Exclude: walk.NewExcluder(sp.Exclusions, r.o.ExcludeDir, r.o.Env),
		MaxFileBytes: limits.MaxFileBytes, Mounts: r.o.Mounts(),
		IncludeNetwork: limits.IncludeNetworkMounts, IncludeRemovable: limits.IncludeRemovable,
		Cache: cache, Rules: sp.RulesKey, Guard: guard, Resume: resumeFrom,
	}
	stats, err := walk.Walk(ctx, o, func(f walk.File) error {
		j.files.Add(1)
		return r.scanFile(ctx, sp, rep, cache, f, timeout, &c)
	})
	c.skipped += stats.FilesSkipped()
	c.errors += stats.Errors
	tcc = tcc || stats.TCCDenied
	if cache != nil {
		if serr := cache.Save(); serr != nil {
			log.Printf("YARA: %v", serr)
		}
	}

	cause := context.Cause(ctx)
	if ctx.Err() != nil && sp.Trigger == yara.TriggerScheduled && (errors.Is(cause, errShutdown) || errors.Is(cause, errPreempted)) {
		r.checkpoint(sp, rep, c, tcc, stats.Checkpoint)
		log.Printf("YARA: scan %s stopped (%v); it continues later", sp.ScanID, cause)
		return
	}
	state := yara.ScanCompleted
	switch {
	case err == nil:
	case errors.Is(err, walk.ErrPartial):
		state = yara.ScanPartial
	case ctx.Err() != nil:
		state = yara.ScanCancelled
	default:
		state = yara.ScanFailed
	}
	sum := rep.Summary(state, c.scanned, c.skipped, c.errors)
	if qerr := r.o.Queue.Add([]yara.Event{sum}); qerr != nil {
		log.Printf("YARA: could not queue the summary of scan %s: %v", sp.ScanID, qerr)
	}
	r.finish(sp, sum.Summary, stats.Checkpoint)
	if r.o.OnScanEnd != nil {
		r.o.OnScanEnd(sum.Summary, tcc)
	}
	why := ""
	if err != nil && state != yara.ScanPartial {
		why = fmt.Sprintf(": %v", errOr(cause, err))
	}
	log.Printf("YARA: scan %s %s: %d files scanned, %d skipped, %d errors, %d matches%s",
		sp.ScanID, state, c.scanned, c.skipped, c.errors, sum.Summary.Matches, why)
}

func errOr(cause, err error) error {
	if cause != nil {
		return cause
	}
	return err
}

// scanFile scans one listed file and queues its match events.
func (r *Runner) scanFile(ctx context.Context, sp spec, rep *report.Scan, cache *walk.Cache, f walk.File, timeout time.Duration, c *counts) error {
	start := time.Now()
	out := r.o.Scanner.ScanFile(ctx, sp.Active.Rules, f, sp.RulesetIDs, timeout)
	r.busy.Add(int64(time.Since(start)))
	if ctx.Err() != nil {
		return context.Cause(ctx) // the file is scanned again on resume
	}
	if out.Status != WorkerFailed {
		c.workerFails = 0
	}
	switch out.Status {
	case Scanned:
	case Skipped:
		c.skipped++
		return nil
	case ReadError:
		c.errors++
		return nil
	case NoRules:
		return errNoRules
	default:
		c.errors++
		if c.workerFails++; c.workerFails >= maxWorkerFailures {
			return errWorkers
		}
		return nil
	}
	c.scanned++
	result := walk.Clean
	if len(out.Matches) > 0 {
		result = walk.Matched
		evs, err := rep.Matches(report.FileResult{Path: f.Path, SHA256: out.SHA256, Size: out.Size,
			MTime: time.Unix(0, f.Key.MTime), Hits: hits(sp.Active, out.Matches)})
		if err == nil && len(evs) > 0 {
			err = r.o.Queue.Add(evs)
		}
		if err != nil {
			log.Printf("YARA: scan %s: match events not queued: %v", sp.ScanID, err)
			c.errors++
			return nil // not cached: the next scan reports it again
		}
	}
	if cache != nil {
		cache.Store(f.Key, sp.RulesKey, result)
	}
	return nil
}

// hits turns the worker's matches into report hits; the namespace is the
// ruleset id.
func hits(a *ruleset.Active, ms []engine.Match) []report.Hit {
	out := make([]report.Hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, report.Hit{RulesetID: m.Namespace, RulesetRevision: a.Revision(m.Namespace),
			Rule: m.Rule, Namespace: m.Namespace, Tags: m.Tags, Meta: m.Meta, StringIDs: m.StringIDs})
	}
	return out
}

// checkpoint saves a stopped scheduled scan so it continues later.
func (r *Runner) checkpoint(sp spec, rep *report.Scan, c counts, tcc bool, cp *walk.Checkpoint) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	st, err := loadState(r.o.StatePath)
	if err != nil {
		log.Printf("YARA: %v", err)
	}
	ss := st.Schedules[sp.ScheduleID]
	if ss == nil {
		ss = &schedState{Seen: r.o.Now().UTC()}
		st.Schedules[sp.ScheduleID] = ss
	}
	res := &resume{RulesKey: sp.RulesKey, Scan: &interrupted{ScanID: sp.ScanID, Started: rep.Started,
		Scanned: c.scanned, Skipped: c.skipped, Errors: c.errors, TCCDenied: tcc, Progress: rep.Progress()}}
	if cp != nil {
		res.Checkpoint = *cp
	} else {
		res.Checkpoint = walk.Checkpoint{RootsKey: walk.RootsKey(sp.Roots)}
	}
	ss.Resume = res
	if err := st.save(r.o.StatePath); err != nil {
		log.Printf("YARA: %v", err)
	}
}

// finish records an ended scan: the last scan, and for a schedule its last
// run and, after a partial scan, where the next one starts.
func (r *Runner) finish(sp spec, sum *yara.ScanSummary, cp *walk.Checkpoint) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	st, err := loadState(r.o.StatePath)
	if err != nil {
		log.Printf("YARA: %v", err)
	}
	st.LastScan = sum
	if sp.ScheduleID != "" {
		ss := st.Schedules[sp.ScheduleID]
		if ss == nil {
			ss = &schedState{Seen: r.o.Now().UTC()}
			st.Schedules[sp.ScheduleID] = ss
		}
		ss.LastRun, ss.Resume = r.o.Now().UTC(), nil
		if sum.State == yara.ScanPartial && cp != nil {
			ss.Resume = &resume{RulesKey: sp.RulesKey, Checkpoint: *cp}
		}
	}
	if err := st.save(r.o.StatePath); err != nil {
		log.Printf("YARA: %v", err)
	}
}

// skipCache opens the skip cache on first use.
func (r *Runner) skipCache() *walk.Cache {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cache == nil && r.o.SkipCachePath != "" {
		c, err := walk.OpenCache(r.o.SkipCachePath, r.o.Env.GOOS)
		if err != nil {
			log.Printf("YARA: %v", err)
		}
		r.cache = c
	}
	return r.cache
}

// rulesKey identifies the ruleset set a scan uses (id and revision of each),
// for the skip cache and checkpoints.
func rulesKey(a *ruleset.Active, ids []string) string {
	rs := a.Bundle.RulesetsFor(ids)
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s@%d", strings.ToLower(r.ID), r.Revision))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
