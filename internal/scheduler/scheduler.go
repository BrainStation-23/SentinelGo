package scheduler

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/osinfo"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/sanitize"
	agentsvc "sentinelgo/internal/service/agent"
	authsvc "sentinelgo/internal/service/auth"
	swsvc "sentinelgo/internal/service/software"
	"sentinelgo/internal/store"
	"sentinelgo/internal/updater"
)

// Task represents a scheduled task with dependencies
type Task struct {
	Name         string
	Interval     time.Duration
	Dependencies []string
	Handler      TaskHandler
	Running      atomic.Bool
	LastRun      time.Time
	Enabled      bool

	// consecutiveFailures counts back-to-back handler failures; it resets to 0 on
	// the first success. alerted gates emergency logging so a sustained outage
	// emits exactly one alert (and one recovery line), not one per tick. Both are
	// atomic because the counter carries across the initial-run goroutine and the
	// per-tick goroutines (which never overlap for one task, see runTaskHandler).
	consecutiveFailures atomic.Int32
	alerted             atomic.Bool
}

// TaskHandler defines the interface for task execution
type TaskHandler func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error

// Scheduler manages centralized task execution with dependencies
type Scheduler struct {
	tasks     map[string]*Task
	taskOrder []string // Execution order based on dependencies
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	running   atomic.Bool
}

// NewScheduler creates a new task scheduler
func NewScheduler() *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		tasks:     make(map[string]*Task),
		taskOrder: []string{},
		ctx:       ctx,
		cancel:    cancel,
	}
}

// AddTask adds a task to the scheduler
func (s *Scheduler) AddTask(task *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[task.Name]; exists {
		return fmt.Errorf("task %s already exists", task.Name)
	}

	s.tasks[task.Name] = task

	// Recalculate task order based on dependencies
	if err := s.calculateTaskOrder(); err != nil {
		delete(s.tasks, task.Name)
		return err
	}

	return nil
}

// calculateTaskOrder determines execution order based on dependencies
func (s *Scheduler) calculateTaskOrder() error {
	visited := make(map[string]bool)
	visiting := make(map[string]bool)
	order := []string{}

	var visit func(name string) error
	visit = func(name string) error {
		if visiting[name] {
			return fmt.Errorf("circular dependency detected involving task %s", name)
		}
		if visited[name] {
			return nil
		}

		visiting[name] = true
		task, exists := s.tasks[name]
		if !exists {
			return fmt.Errorf("task %s not found", name)
		}

		for _, dep := range task.Dependencies {
			if _, depExists := s.tasks[dep]; !depExists {
				return fmt.Errorf("dependency task %s not found for task %s", dep, name)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}

		visiting[name] = false
		visited[name] = true
		order = append(order, name)
		return nil
	}

	for name := range s.tasks {
		if !visited[name] {
			if err := visit(name); err != nil {
				return err
			}
		}
	}

	s.taskOrder = order
	return nil
}

// Start begins the scheduler execution
func (s *Scheduler) Start(cfg *config.Config, authSvc *authsvc.Service) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("scheduler is already running")
	}

	log.Printf("Starting task scheduler with %d tasks", len(s.tasks))

	// Run initial tasks in dependency order
	s.runInitialTasks(cfg, authSvc)

	// Start periodic execution
	s.wg.Add(1)
	go s.runPeriodicTasks(cfg, authSvc)

	return nil
}

// runTaskHandler invokes a task handler with panic recovery. A panic in a
// collector or handler (e.g. a nil dereference or a type-assertion bug) would
// otherwise unwind through the task goroutine and crash the entire agent. Here
// it is logged and converted to an error so the one task fails while the rest of
// the agent keeps running.
func runTaskHandler(ctx context.Context, name string, h TaskHandler, cfg *config.Config, authSvc *authsvc.Service) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Task %s panicked (recovered): %v", sanitize.ForLog(name), r)
			err = fmt.Errorf("task %s panicked: %v", name, r)
		}
	}()
	return h(ctx, cfg, authSvc)
}

// taskFailureThreshold is how many back-to-back failures a task must hit before
// it is treated as an emergency. A single failure is routine (a network blip);
// this many in a row across the task's interval signals a real, sustained outage
// — e.g. updates that keep failing or a sync that can't reach the backend.
const taskFailureThreshold = 3

// observeTaskResult updates a task's consecutive-failure counter and records an
// emergency the first time a task crosses the threshold, plus a single recovery
// line the first time it succeeds again. Called from both the initial and the
// periodic run paths; those never run a given task concurrently, so the atomic
// counter simply carries across the boundary.
func observeTaskResult(t *Task, err error) {
	if err != nil {
		n := t.consecutiveFailures.Add(1)
		if n >= taskFailureThreshold && t.alerted.CompareAndSwap(false, true) {
			emergencylog.Record("sync", "task %s failed %d consecutive times: %v", t.Name, n, err)
		}
		return
	}
	t.consecutiveFailures.Store(0)
	if t.alerted.CompareAndSwap(true, false) {
		emergencylog.Record("sync", "task %s recovered after repeated failures", t.Name)
	}
}

// runInitialTasks executes all enabled tasks once in dependency order using a
// single background goroutine so the ordering is respected without blocking
// Scheduler.Start. If a task fails its LastRun is still recorded so dependent
// tasks are not permanently blocked by a one-off failure.
func (s *Scheduler) runInitialTasks(cfg *config.Config, authSvc *authsvc.Service) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Running initial tasks in dependency order")

		for _, taskName := range s.taskOrder {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			task := s.tasks[taskName]
			if !task.Enabled {
				log.Printf("Task %s is disabled, skipping initial run", taskName)
				continue
			}

			if !task.Running.CompareAndSwap(false, true) {
				log.Printf("Task %s is already running, skipping initial run", taskName)
				continue
			}

			log.Printf("Running initial task: %s", taskName)
			err := runTaskHandler(s.ctx, taskName, task.Handler, cfg, authSvc)
			if err != nil {
				log.Printf("Initial task %s failed: %v", taskName, err)
			} else {
				log.Printf("Initial task %s completed successfully", taskName)
			}
			observeTaskResult(task, err)
			// Always record LastRun so dependent tasks are not permanently
			// blocked by a failure in this dependency.
			task.LastRun = time.Now()
			task.Running.Store(false)
		}
	}()
}

// runPeriodicTasks handles periodic execution of enabled tasks.
// A 1-second heartbeat ticker gates the inner loop so the goroutine blocks
// instead of busy-spinning with a short sleep.
func (s *Scheduler) runPeriodicTasks(cfg *config.Config, authSvc *authsvc.Service) {
	defer s.wg.Done()

	tickers := make(map[string]*time.Ticker)
	defer func() {
		for _, ticker := range tickers {
			ticker.Stop()
		}
	}()

	for name, task := range s.tasks {
		if task.Enabled && task.Interval > 0 {
			tickers[name] = time.NewTicker(task.Interval)
			log.Printf("Started ticker for task %s with interval %v", name, task.Interval)
		}
	}

	heartbeat := time.NewTicker(time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Scheduler stopping, shutting down all tasks")
			return
		case <-heartbeat.C:
			for name, ticker := range tickers {
				select {
				case <-ticker.C:
					task := s.tasks[name]
					if !task.Enabled {
						continue
					}

					if !s.checkDependencies(task) {
						log.Printf("Task %s dependencies not met, skipping this run", name)
						continue
					}

					s.wg.Add(1)
					go func(t *Task, taskName string) {
						defer s.wg.Done()

						if !t.Running.CompareAndSwap(false, true) {
							log.Printf("Task %s is already running, skipping this tick", taskName)
							return
						}
						defer t.Running.Store(false)

						log.Printf("Running periodic task: %s", taskName)
						err := runTaskHandler(s.ctx, taskName, t.Handler, cfg, authSvc)
						if err != nil {
							log.Printf("Periodic task %s failed: %v", taskName, err)
						} else {
							log.Printf("Periodic task %s completed successfully", taskName)
						}
						observeTaskResult(t, err)
						// Always update LastRun so dependent tasks are not
						// permanently blocked by a one-off failure.
						t.LastRun = time.Now()
					}(task, name)
				default:
				}
			}
		}
	}
}

// checkDependencies verifies that all dependencies have run successfully
func (s *Scheduler) checkDependencies(task *Task) bool {
	for _, depName := range task.Dependencies {
		depTask, exists := s.tasks[depName]
		if !exists {
			log.Printf("Dependency task %s not found for task %s", depName, task.Name)
			return false
		}

		// Check if dependency has run at least once
		if depTask.LastRun.IsZero() {
			log.Printf("Dependency task %s has not run yet for task %s", depName, task.Name)
			return false
		}
	}
	return true
}

// Stop gracefully shuts down the scheduler
func (s *Scheduler) Stop() {
	if !s.running.CompareAndSwap(true, false) {
		return // Already stopped
	}

	log.Printf("Stopping task scheduler...")

	// Cancel context to stop all running tasks
	s.cancel()

	// Wait for all tasks to complete
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("All tasks stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Printf("Warning: Some tasks did not stop within 30 seconds")
	}
}

// GetTaskStatus returns the current status of all tasks
func (s *Scheduler) GetTaskStatus() map[string]TaskStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := make(map[string]TaskStatus)
	for name, task := range s.tasks {
		status[name] = TaskStatus{
			Name:     name,
			Enabled:  task.Enabled,
			Running:  task.Running.Load(),
			LastRun:  task.LastRun,
			Interval: task.Interval,
		}
	}
	return status
}

// TaskStatus represents the current status of a task
type TaskStatus struct {
	Name     string
	Enabled  bool
	Running  bool
	LastRun  time.Time
	Interval time.Duration
}

// CreateDefaultTasks returns the default scheduled tasks.
//
// Intervals are left at their zero values here; configureScheduledTasks in
// MainIntegration replaces them from config.json before the tasks are
// registered with the scheduler.
//
// Tasks have no inter-dependencies: each one is self-sufficient and can
// fail independently without blocking the others.
//
// Audit-log collection is managed by MainIntegration as a long-lived
// service and is NOT included here.
func CreateDefaultTasks() []*Task {
	return []*Task{
		{
			// Proactively refresh the JWT well before it expires. Without this,
			// the access token (typically ~1h) lapsed silently after startup and
			// every reporting path stopped while the process still looked healthy.
			Name:         "token-refresh",
			Interval:     time.Minute,
			Dependencies: []string{},
			Handler:      handleTokenRefresh,
			Enabled:      true,
		},
		{
			Name:         "auto-update",
			Interval:     1 * time.Hour, // overridden from config.AutoUpdateInterval
			Dependencies: []string{},
			Handler:      handleAutoUpdate,
			Enabled:      true,
		},
		{
			Name:         "agent-info-update",
			Interval:     time.Hour, // overridden from config.AgentInfoUpdateInterval
			Dependencies: []string{},
			Handler:      handleAgentInfoUpdate,
			Enabled:      true,
		},
		{
			Name:         "software-sync",
			Interval:     5 * time.Minute, // overridden from config.UpdateInterval
			Dependencies: []string{},
			Handler:      handleSoftwareSync,
			Enabled:      true,
		},
	}
}

// Task handlers

// tokenRefreshSkew is how far before expiry the access token is proactively
// refreshed. With a ~1h Supabase token this leaves comfortable margin.
const tokenRefreshSkew = 5 * time.Minute

func handleTokenRefresh(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
	if authSvc == nil {
		return nil
	}
	if !authsvc.ShouldRefresh(cfg.AccessToken, tokenRefreshSkew) {
		return nil
	}
	if authSvc.NeedsReprovision() {
		// agent-login has rejected the stored credentials; there is nothing this
		// task can do until an operator re-provisions the agent. Stay quiet rather
		// than logging a guaranteed-to-fail attempt every minute.
		return nil
	}
	log.Printf("Scheduler: access token at/near expiry, recovering session")
	// Recover (refresh→agent-login) is breaker-gated: while the breaker is open it
	// returns immediately without a network call, throttling repeated failures to
	// the breaker's reset cadence instead of every tick.
	return authSvc.Recover(ctx, cfg)
}

func handleAutoUpdate(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
	// Jitter: spread checks across up to 5 minutes to avoid thundering herd
	// when many agents start simultaneously.
	jitter := time.Duration(rand.Intn(5*60)) * time.Second
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(jitter):
	}
	log.Printf("Running auto-update check")
	return updater.CheckAndApplyWithRetry(ctx, cfg)
}

// collectTimeout caps the entire agent-info-update cycle (osinfo + RPC).
// osinfo.Collect is synchronous and has no context parameter; without this
// bound, a hung gopsutil call would leave task.Running=true indefinitely and
// silently block every subsequent periodic tick.
const collectTimeout = 90 * time.Second

func handleAgentInfoUpdate(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
	if authSvc != nil && !authSvc.Healthy() {
		// Session is unrecoverable right now (breaker open or credentials rejected).
		// Skip the upload instead of firing a request that is guaranteed to 401 —
		// the token-refresh task is what re-establishes auth.
		log.Printf("Scheduler: auth degraded, skipping agent-info-update until session recovers")
		return nil
	}

	log.Printf("Running agent info update")

	tctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()

	type result struct{ info *shared.SystemInfo }
	ch := make(chan result, 1)
	go func() { ch <- result{osinfo.Collect()} }()

	var sysInfo *shared.SystemInfo
	select {
	case <-tctx.Done():
		return fmt.Errorf("osinfo.Collect timed out after %v", collectTimeout)
	case r := <-ch:
		sysInfo = r.info
	}

	if sysInfo == nil {
		// osinfo.Collect returns nil when host.Info() fails. Skip this cycle
		// rather than dereferencing nil downstream (which panicked the task
		// goroutine and, with no recover, killed the whole agent).
		return fmt.Errorf("system info collection returned no data; skipping this cycle")
	}
	agentSvc := agentsvc.NewAgentService()
	if authSvc == nil {
		return agentSvc.UpdateAgentInfo(tctx, cfg, sysInfo)
	}
	// On a 401 mid-run, recover the session (refresh→login) and retry once.
	return authSvc.DoWithAuthRetry(tctx, cfg, func() error {
		return agentSvc.UpdateAgentInfo(tctx, cfg, sysInfo)
	})
}

func handleSoftwareSync(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
	if !cfg.SoftwareSyncEnabled {
		log.Printf("Software sync is disabled")
		return nil
	}

	if authSvc != nil && !authSvc.Healthy() {
		log.Printf("Scheduler: auth degraded, skipping software-sync until session recovers")
		return nil
	}

	log.Printf("Running software sync")

	configDir := filepath.Dir(cfg.Path)
	swStore, err := store.NewSoftwareStore(filepath.Join(configDir, "software.sqlite"))
	if err != nil {
		return fmt.Errorf("open software store: %w", err)
	}
	defer func() {
		if err := swStore.Close(); err != nil {
			log.Printf("Failed to close software store: %v", err)
		}
	}()

	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(cfg.SupabaseURL)
	svc.SetEdgeFunctionConfig(cfg.SupabaseURL+"/functions/v1/sync-software", cfg.AccessToken)

	syncTime := time.Now()
	freshList, scannedSources := svc.GetSoftwareList()
	if len(scannedSources) == 0 {
		// Every collector failed this cycle. SyncBatch will not reconcile any source
		// (which would otherwise demote the entire catalog to "uninstalled"); the
		// last-known catalog is preserved and re-uploaded below on the next retry.
		log.Printf("[software] no software source scanned successfully; keeping last-known catalog")
	}

	if err := swStore.SyncBatch(freshList, syncTime, scannedSources); err != nil {
		// Non-fatal: log the error but continue with whatever is in the catalog.
		log.Printf("[software] store sync error: %v", err)
	}

	// Always queue an upload: either the fresh scan succeeded or we need to
	// retry the previous failed upload.
	if err := swStore.QueueSync(); err != nil {
		log.Printf("[software] queue sync error: %v", err)
	}

	catalog, err := swStore.GetAll()
	if err != nil {
		return fmt.Errorf("read software catalog: %w", err)
	}
	if len(catalog) == 0 {
		// Nothing to upload; clear the queue marker so we don't retry an empty catalog.
		_ = swStore.ClearSync()
		log.Printf("Software catalog is empty, skipping upload")
		return nil
	}

	sanitizedCatalogCount := sanitize.ForLog(fmt.Sprintf("%d", len(catalog)))
	sanitizedFreshCount := sanitize.ForLog(fmt.Sprintf("%d", len(freshList)))
	log.Printf("Software sync: %s catalog entries (%s fresh)", sanitizedCatalogCount, sanitizedFreshCount)

	sendSoftware := func() error { return svc.SendByRPC(ctx, cfg.DeviceID, catalog, cfg) }
	if authSvc != nil {
		// On a 401 mid-run, recover the session (refresh→login) and retry once.
		sendSoftware = func() error {
			return authSvc.DoWithAuthRetry(ctx, cfg, func() error {
				return svc.SendByRPC(ctx, cfg.DeviceID, catalog, cfg)
			})
		}
	}
	if err := sendSoftware(); err != nil {
		// Leave the queue marker so the next tick retries the upload.
		return fmt.Errorf("send software data: %w", err)
	}

	// Upload succeeded: clear the pending marker.
	if err := swStore.ClearSync(); err != nil {
		log.Printf("[software] clear sync error: %v", err)
	}
	return nil
}
