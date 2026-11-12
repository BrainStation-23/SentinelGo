package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/scheduler"
	agentsvc "sentinelgo/internal/service/agent"
	authsvc "sentinelgo/internal/service/auth"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/store"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
	"sentinelgo/internal/yara/report"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/scan"
	"sentinelgo/internal/yara/walk"
	"sentinelgo/internal/yara/watch"
)

// yaraSyncTick is how often the yara-ruleset-sync task wakes up; the Syncer
// decides whether a poll is due (every 15 minutes, or sooner when pushed).
const yaraSyncTick = ruleset.PollInterval / 15

// yaraWorkers is the YARA pool's size: one worker, separate from file DLP's
// pool, so a long scan never starves DLP's blocking decisions (#412).
const yaraWorkers = 1

// YARA scheduler ticks (#414, #415): due scans are checked every minute
// (each schedule's own offset spreads the fleet), queued events uploaded
// every minute.
const (
	yaraScanTick      = time.Minute
	yaraEventSyncTick = time.Minute
)

// Shutdown bounds (#416): the running scan has yaraScanStopTimeout to
// checkpoint; the last upload of queued events gets yaraFlushTimeout.
var (
	yaraScanStopTimeout = 15 * time.Second
	yaraFlushTimeout    = 5 * time.Second
)

// yaraState is the threat hunting runtime (#411-#416).
type yaraState struct {
	cfg    *config.Config
	pool   *scanworker.Pool
	syncer *ruleset.Syncer
	runner *scan.Runner
	// onWrite scans files as they are written (#418); nil with
	// yara_enabled false.
	onWrite *scan.OnWrite
	events  *store.YARAEventStore
	upload  *report.EventSync

	statusPath string
	statusMu   sync.Mutex
	lastStatus []byte
}

// startYARA starts threat hunting after auth and DLP, before the task
// manager accepts yara-scan (#416): the ruleset sync (#411), the scan worker
// pool (#412), the event queue and its upload (#415), the scan scheduler and
// the yara-scan / yara-scan-cancel hooks (#414). Workers start only when a
// bundle has rules to compile: the backend sends a disabled bundle to agents
// that don't advertise yara_scan_v1.
//
// With yara_enabled false in config.json the sync still polls, so the
// console sees state disabled, and queued events are still uploaded, but no
// worker starts and no scan runs. Errors are logged, never fatal.
func (mi *MainIntegration) startYARA() {
	cfg := mi.cfg
	dir := filepath.Dir(cfg.Path)
	y := &yaraState{cfg: cfg, statusPath: filepath.Join(dir, scan.StatusFileName)}

	exe, err := os.Executable()
	if err != nil && cfg.YARAEnabled {
		log.Printf("Warning: YARA not started: %v", err)
		return
	}
	client := ruleset.NewClient(func() ruleset.Supabase { return supabase.FromConfig(cfg) })
	opts := ruleset.Options{
		Fetcher:         client,
		Downloader:      client,
		Retry:           ruleset.Retrier(authRetrier(cfg, mi.authSvc)),
		Cache:           ruleset.NewCache(filepath.Join(dir, ruleset.DirName)),
		AgentVersion:    config.Version,
		EngineVersion:   engine.EngineVersion(),
		LocallyDisabled: !cfg.YARAEnabled,
	}
	if cfg.YARAEnabled {
		y.pool = scanworker.NewPool(yaraPoolOptions(exe))
		opts.Compiler = poolCompiler{y.pool}
		opts.WorkerHealthy = func() bool { return !y.pool.Health().Disabled }
		// A disabled bundle stops the running scan (contract §2); on-write
		// scanning follows the bundle's on_write block (#418).
		// The sync runs only from tasks scheduled at the end of startYARA,
		// so both fields are set by then.
		opts.OnChange = func(a *ruleset.Active) {
			if !a.Enabled() && y.runner != nil {
				y.runner.Disable()
			}
			if y.onWrite != nil {
				y.onWrite.Apply(a)
			}
		}
	} else {
		log.Printf("YARA: disabled on this device (yara_enabled=false); reporting state disabled, no scans")
	}
	y.syncer = ruleset.New(opts)

	q, err := store.NewYARAEventStore(filepath.Join(dir, store.YARAEventsDBName))
	if err != nil {
		log.Printf("Warning: YARA event queue unavailable: %v", err)
	} else {
		y.events = q
		y.upload = report.NewEventSync(q, report.NewClient(func() report.RPC { return supabase.FromConfig(cfg) }),
			report.Retrier(authRetrier(cfg, mi.authSvc)))
	}
	if cfg.YARAEnabled && q != nil {
		agentID := cfg.AgentID
		if agentID == "" {
			agentID = cfg.DeviceID
		}
		y.runner = scan.New(scan.Options{
			Active:         y.syncer.Active,
			Scanner:        poolScanner{y.pool},
			Queue:          q,
			Dedupe:         q,
			AgentID:        agentID,
			StatePath:      filepath.Join(dir, scan.StateFileName),
			SkipCachePath:  filepath.Join(dir, scan.SkipCacheFileName),
			Env:            walk.DefaultEnv(),
			Mounts:         yaraMounts,
			ExcludeDir:     filepath.Dir(exe),
			OnBattery:      walk.OnBattery,
			BeforeOnDemand: y.syncer.PollNow,
			OnScanEnd: func(sum *yara.ScanSummary, tcc bool) {
				y.syncer.SetLastScan(sum)
				y.syncer.SetTCCDenied(tcc)
				y.syncer.PollNow() // report the new last_scan soon
				y.writeStatus()
			},
		})
		y.syncer.SetLastScan(y.runner.LastScan())
		y.onWrite = scan.NewOnWrite(y.runner, scan.OnWriteOptions{Watch: yaraWatch})
		y.onWrite.Apply(y.syncer.Active())
	}

	tasks := []*scheduler.Task{
		{Name: yara.TaskSync, Interval: yaraSyncTick, Enabled: true, Handler: y.syncHandler()},
	}
	if y.upload != nil {
		tasks = append(tasks, &scheduler.Task{Name: yara.TaskEventSync, Interval: yaraEventSyncTick, Enabled: true, Handler: yaraEventSyncHandler(y.upload)})
	}
	if y.runner != nil {
		tasks = append(tasks, &scheduler.Task{Name: yara.TaskScheduler, Interval: yaraScanTick, Enabled: true, Handler: y.scanTickHandler()})
	}
	for _, t := range tasks {
		if err := mi.scheduler.AddTask(t); err != nil {
			log.Printf("Warning: YARA task %s not scheduled: %v", t.Name, err)
		}
	}
	mi.yara = y
	if y.runner != nil {
		native.SetYARAScanner(yaraTaskHook{y})
	}
	agentsvc.SetYARASource(y.summary)
	y.writeStatus()
}

// stopYARA shuts threat hunting down after the scheduler and task manager
// (#416): cancel and checkpoint the scan, stop the workers, then try once to
// upload what is queued and close the queue.
func (mi *MainIntegration) stopYARA() {
	y := mi.yara
	if y == nil {
		return
	}
	mi.yara = nil
	native.SetYARAScanner(nil)
	agentsvc.SetYARASource(nil)
	if y.onWrite != nil {
		y.onWrite.Stop() // its window's summary is queued before the flush below
	}
	if y.runner != nil {
		y.runner.Stop(yaraScanStopTimeout)
	}
	if y.pool != nil {
		y.pool.Stop()
	}
	y.writeStatus()
	if y.upload != nil && (mi.authSvc == nil || mi.authSvc.Healthy()) {
		ctx, cancel := context.WithTimeout(context.Background(), yaraFlushTimeout)
		if _, err := y.upload.Sync(ctx); err != nil {
			log.Printf("YARA: events stay queued for the next start: %v", err)
		}
		cancel()
	}
	if y.events != nil {
		if err := y.events.Close(); err != nil {
			log.Printf("Warning: Failed to close YARA event store: %v", err)
		}
	}
}

// syncHandler polls when due, unless the session is degraded (the
// token-refresh task recovers it). The Syncer wraps each server call in
// DoWithAuthRetry itself (Options.Retry).
func (y *yaraState) syncHandler() scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if !y.syncer.Due() {
			return nil
		}
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping %s until session recovers", yara.TaskSync)
			return nil
		}
		err := y.syncer.Sync(ctx)
		y.writeStatus()
		return err
	}
}

// scanTickHandler starts a due scheduled scan (in the background), has
// on-write scanning pick up new user folders and drives, and keeps the local
// status current.
func (y *yaraState) scanTickHandler() scheduler.TaskHandler {
	return func(context.Context, *config.Config, *authsvc.Service) error {
		if y.onWrite != nil {
			y.onWrite.Apply(y.syncer.Active())
		}
		err := y.runner.Tick()
		y.writeStatus()
		return err
	}
}

// yaraEventSyncHandler uploads queued match and summary events, unless the
// session is degraded. Each batch is wrapped in DoWithAuthRetry.
func yaraEventSyncHandler(es *report.EventSync) scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if authSvc != nil && !authSvc.Healthy() {
			return nil
		}
		n, err := es.Sync(ctx)
		if n > 0 {
			log.Printf("YARA: uploaded %d events", n)
		}
		return err
	}
}

// local returns the status for `sentinelgo yara status`.
func (y *yaraState) local() scan.LocalStatus {
	ls := scan.LocalStatus{UpdatedAt: time.Now().UTC(), LocalEnabled: y.cfg.YARAEnabled, Status: y.syncer.Status()}
	if y.pool != nil {
		h := y.pool.Health()
		ls.Workers = &scan.Workers{Live: h.Workers, Sandbox: h.Sandbox, Failures: h.Failures, Disabled: h.Disabled}
	}
	if y.runner != nil {
		ls.Scanning = y.runner.Current()
		ls.Schedules = y.runner.Schedules()
	}
	if y.onWrite != nil {
		ls.OnWrite = y.onWrite.Status()
	}
	if y.events != nil {
		if rows, _, dropped, err := y.events.Stats(); err == nil {
			ls.QueuedEvents, ls.DroppedEvents = rows, dropped
		}
	}
	return ls
}

// writeStatus saves the local status when it changed (ignoring the time).
func (y *yaraState) writeStatus() {
	ls := y.local()
	stamp := ls.UpdatedAt
	ls.UpdatedAt = time.Time{}
	data, err := json.Marshal(ls)
	if err != nil {
		return
	}
	y.statusMu.Lock()
	defer y.statusMu.Unlock()
	if bytes.Equal(data, y.lastStatus) {
		return
	}
	ls.UpdatedAt = stamp
	if err := scan.WriteStatus(y.statusPath, ls); err != nil {
		log.Printf("YARA: could not write %s: %v", scan.StatusFileName, err)
		return
	}
	y.lastStatus = data
}

// summary is the inventory's threat hunting block (#416).
func (y *yaraState) summary() *yara.Summary {
	ls := y.local()
	s := yara.SummaryOf(ls.Status)
	s.LocalEnabled = y.cfg.YARAEnabled
	s.WorkersHealthy = ls.Workers != nil && !ls.Workers.Disabled
	s.QueuedEvents = ls.QueuedEvents
	if ls.Scanning != nil {
		s.Scanning = ls.Scanning.ScanID
	}
	return &s
}

// yaraTaskHook is what the yara-scan and yara-scan-cancel tasks call.
type yaraTaskHook struct{ y *yaraState }

func (h yaraTaskHook) StartScan(ctx context.Context, p yara.TaskParams) (yara.TaskResult, error) {
	h.y.syncer.Restore(ctx) // a task right after startup: load the cached rules first
	res, err := h.y.runner.StartOnDemand(p)
	if err == nil {
		h.y.writeStatus()
	}
	return res, err
}

func (h yaraTaskHook) CancelScan() string { return h.y.runner.Cancel() }

// yaraWatch starts the on-write watcher (#418) for scan.OnWrite.
func yaraWatch(roots []string, changed func(string), lost func(), gone func(string)) (scan.Watcher, error) {
	w, err := watch.Start(roots, watch.Handler{Changed: changed, Lost: lost, Gone: gone})
	if w == nil {
		return nil, err // no typed nil in the interface
	}
	return w, err
}

// yaraMounts lists removable drives and network shares, which scans skip
// unless the bundle's limits include them.
func yaraMounts() []walk.Mount {
	var out []walk.Mount
	for _, d := range filedlp.ExternalMounts() {
		if d.Mount != "" {
			out = append(out, walk.Mount{Path: d.Mount, Network: d.Type == filedlp.TypeNetworkShare})
		}
	}
	return out
}

// yaraPoolOptions configures the YARA worker pool: one worker, separate from
// file DLP's, at background CPU and IO priority (#412, #413).
func yaraPoolOptions(exe string) scanworker.Options {
	return scanworker.Options{Exe: exe, Workers: yaraWorkers, Name: "YARA scan",
		Env: []string{scanworker.BackgroundEnv + "=1"}}
}

// poolCompiler compiles rule sources in a sandboxed YARA worker.
type poolCompiler struct{ pool *scanworker.Pool }

func (c poolCompiler) Compile(ctx context.Context, srcs []yara.RuleSource) (ruleset.Rules, []yara.CompileResult, error) {
	rules := scanworker.NewYARARules(srcs)
	res, err := c.pool.CompileYARA(ctx, rules)
	if err != nil {
		return nil, nil, err
	}
	return rules, res, nil
}

// poolScanner opens a listed file (without following links, and checking
// it is still the file listed) and has a sandboxed worker scan it.
type poolScanner struct{ pool *scanworker.Pool }

func (s poolScanner) ScanFile(ctx context.Context, rules ruleset.Rules, f walk.File, ids []string, timeout time.Duration) scan.FileOutcome {
	r, ok := rules.(*scanworker.YARARules)
	if !ok {
		return scan.FileOutcome{Status: scan.NoRules}
	}
	fh, err := walk.Open(f)
	switch {
	case errors.Is(err, walk.ErrChanged), errors.Is(err, fs.ErrNotExist):
		return scan.FileOutcome{Status: scan.Skipped}
	case err != nil:
		return scan.FileOutcome{Status: scan.ReadError}
	}
	defer func() { _ = fh.Close() }()
	res := s.pool.ScanYARA(ctx, r, scanworker.YARAScan{File: fh, Size: f.Size, Path: f.Path, RulesetIDs: ids, Timeout: timeout})
	switch res.Status {
	case scanworker.YARAScanned:
		return scan.FileOutcome{Status: scan.Scanned, SHA256: res.SHA256, Size: res.Size, Matches: res.Matches}
	case scanworker.YARATimeout:
		return scan.FileOutcome{Status: scan.Skipped}
	case scanworker.YARAReadError:
		return scan.FileOutcome{Status: scan.ReadError}
	case scanworker.YARANoRules:
		return scan.FileOutcome{Status: scan.NoRules}
	}
	return scan.FileOutcome{Status: scan.WorkerFailed}
}
