package internal

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/hashutil"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	servicessvc "sentinelgo/internal/service/services"
	swsvc "sentinelgo/internal/service/software"
	tasksvc "sentinelgo/internal/service/task"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/updater"
)

// startupTokenSkew is how much validity a stored access token must still have
// for startup to reuse it instead of minting a fresh session via agent-login.
const startupTokenSkew = 5 * time.Minute

// MainIntegration orchestrates the agent's runtime components (auth, scheduler,
// logging, task manager) according to EXECUTION_FLOW.md. It wires together
// collaborators it is given and drives their startup/shutdown ordering; the
// concrete dependencies are supplied at construction time.
type MainIntegration struct {
	cfg            *config.Config
	scheduler      *scheduler.Scheduler
	authSvc        *authsvc.Service
	loggingService *logging.LoggingIntegration
	taskManager    *tasksvc.TaskManager
	servicesStore  *store.ServicesStore
	softwareStore  *store.SoftwareStore
	epmStore       *store.EPMStore
	epmService     *epm.Service
}

// NewMainIntegration wires the production dependencies and returns a ready
// MainIntegration. Use NewMainIntegrationWith to inject collaborators (e.g. in
// tests).
func NewMainIntegration(cfg *config.Config) *MainIntegration {
	return NewMainIntegrationWith(cfg, scheduler.NewScheduler())
}

// NewMainIntegrationWith builds a MainIntegration from injected collaborators,
// allowing callers (and tests) to supply their own scheduler. The auth service,
// logging service, and task manager are created during Start because they
// depend on the validated config and the run context.
func NewMainIntegrationWith(cfg *config.Config, sched *scheduler.Scheduler) *MainIntegration {
	return &MainIntegration{
		cfg:       cfg,
		scheduler: sched,
	}
}

// Start initializes and starts all services according to the execution flow.
// It orchestrates a fixed sequence of init steps; each step is a focused method
// so the ordering is explicit and individually testable.
func (mi *MainIntegration) Start(ctx context.Context) error {
	mi.logStartup()

	// Point the emergency log at the runtime directory (sibling of config.json)
	// before anything else, so even a config-validation failure is recordable.
	// A failure here is non-fatal: Record degrades to echoing to the standard log.
	if err := emergencylog.Init(filepath.Dir(mi.cfg.Path)); err != nil {
		log.Printf("Warning: emergency log init failed (events echo to log only): %v", err)
	}

	// 1. Validate configuration before doing anything that depends on it.
	if err := mi.cfg.ValidateConfiguration(); err != nil {
		emergencylog.Record("startup", "config validation failed: %v", err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// 2. Kick off a startup update check (async, best-effort).
	mi.maybeStartupUpdateCheck(ctx)

	// 3. Initialize authentication (service, session, preemptive refresh).
	mi.initAuth(ctx)

	// 4. Build and register the scheduled tasks.
	if err := mi.configureScheduledTasks(); err != nil {
		return err
	}

	// 5. Start the audit log service if enabled.
	if err := mi.startLoggingService(ctx); err != nil {
		return err
	}

	// 6. Start the task manager (polling + execution) if enabled.
	mi.startTaskManager(ctx)

	// 7. Start Endpoint Privilege Management (EPM) if enabled. Off by default;
	// failures are logged, never fatal, matching every other optional component.
	mi.startEPM(ctx)

	// 8. Start the task scheduler.
	if err := mi.scheduler.Start(mi.cfg, mi.authSvc); err != nil {
		emergencylog.Record("startup", "scheduler failed to start: %v", err)
		return fmt.Errorf("failed to start scheduler: %w", err)
	}

	log.Printf("SentinelGo main integration started successfully")
	return nil
}

// servicesDBPath returns the path for the services SQLite database, placed in
// the same directory as config.json.
func (mi *MainIntegration) servicesDBPath() string {
	return filepath.Join(filepath.Dir(mi.cfg.Path), "sentinelgo_services.db")
}

// logStartup logs the startup banner and key config flags.
func (mi *MainIntegration) logStartup() {
	log.Printf("Starting SentinelGo main integration...")
	log.Printf("Config path: %s", sanitize.ForLog(mi.cfg.Path))
	log.Printf("Audit logs enabled: %v", mi.cfg.AuditLogsEnabled)
	log.Printf("Log storage enabled: %v", mi.cfg.LogStorageEnabled)
}

// maybeStartupUpdateCheck performs an async startup update check when
// auto-update is enabled. Failures are logged but do not block startup.
func (mi *MainIntegration) maybeStartupUpdateCheck(ctx context.Context) {
	if !mi.cfg.AutoUpdate {
		return
	}
	log.Println("Auto-update is enabled, performing startup update check...")
	go func() {
		if err := updater.StartupUpdateCheck(ctx, mi.cfg); err != nil {
			log.Printf("Startup update check failed: %v", err)
		}
	}()
}

// initAuth creates the auth service and establishes a session. It mints a fresh
// session via agent-login unless a stored access token is still comfortably
// valid (a quick restart), in which case that token is reused. Failures are
// non-fatal: the scheduler's recovery loop keeps retrying, gated by the auth
// circuit breaker, so a transient outage at boot does not crash the service.
func (mi *MainIntegration) initAuth(ctx context.Context) {
	mi.authSvc = authsvc.NewService(mi.cfg.SupabaseURL, mi.cfg.SupabaseKey)

	if mi.cfg.AccessToken != "" && !authsvc.ShouldRefresh(mi.cfg.AccessToken, startupTokenSkew) {
		if err := mi.authSvc.InitSession(mi.cfg); err == nil {
			log.Printf("Auth: reusing stored access token (still valid)")
			return
		} else {
			log.Printf("Warning: session init from stored token failed: %v", err)
		}
	}

	if err := mi.authSvc.Login(ctx, mi.cfg); err != nil {
		log.Printf("Warning: startup agent-login failed (will retry in background): %v", err)
	}
}

// configureScheduledTasks builds the default task set, applies config-driven
// intervals and enable flags, and registers each task with the scheduler.
func (mi *MainIntegration) configureScheduledTasks() error {
	tasks := scheduler.CreateDefaultTasks()

	for i := range tasks {
		switch tasks[i].Name {
		case "auto-update":
			tasks[i].Enabled = mi.cfg.AutoUpdate
			tasks[i].Interval = mi.cfg.GetAutoUpdateInterval()
		case "agent-info-update":
			tasks[i].Interval = mi.cfg.GetAgentInfoUpdateInterval()
		case "software-sync":
			tasks[i].Interval = mi.cfg.GetSoftwareInfoUpdateInterval()
			if h := mi.softwareSyncHandler(); h != nil {
				tasks[i].Handler = h
			}
		}
	}

	// Append services-collect task with a closure that captures the store so the
	// DB is opened once and stays open for the lifetime of the scheduler.
	if servicesTask := mi.buildServicesTask(); servicesTask != nil {
		tasks = append(tasks, servicesTask)
	}

	// Append task-db-cleanup: prune completed tasks older than 7 days once a week
	// so the local SQLite queue does not grow unboundedly on long-running agents.
	tasks = append(tasks, mi.buildTaskDBCleanupTask())

	for _, task := range tasks {
		if err := mi.scheduler.AddTask(task); err != nil {
			return fmt.Errorf("failed to add task %s: %w", task.Name, err)
		}
	}

	log.Printf("Scheduler intervals: agent-info=%v, software-sync=%v, auto-update=%v, token-refresh=1m, services-collect=%v",
		mi.cfg.GetAgentInfoUpdateInterval(),
		mi.cfg.GetSoftwareInfoUpdateInterval(),
		mi.cfg.GetAutoUpdateInterval(),
		mi.cfg.GetServicesUpdateInterval(),
	)
	return nil
}

// buildTaskDBCleanupTask returns a weekly scheduled task that purges completed
// (success/failed) task rows older than 7 days from the local SQLite queue.
// Without this, a long-running agent accumulates completed rows indefinitely.
// The task is always enabled; failures are non-fatal and logged.
func (mi *MainIntegration) buildTaskDBCleanupTask() *scheduler.Task {
	return &scheduler.Task{
		Name:     "task-db-cleanup",
		Interval: 7 * 24 * time.Hour,
		Enabled:  true,
		Handler: func(ctx context.Context, cfg *config.Config, _ *authsvc.Service) error {
			tm, err := tasksvc.NewTaskManager(cfg)
			if err != nil {
				return fmt.Errorf("task-db-cleanup: open task store: %w", err)
			}
			defer func() {
				if closeErr := tm.Close(); closeErr != nil {
					log.Printf("task-db-cleanup: close task manager: %v", closeErr)
				}
			}()
			cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
			if err := tm.CleanupCompletedTasks(cutoff); err != nil {
				return fmt.Errorf("task-db-cleanup: %w", err)
			}
			log.Printf("task-db-cleanup: pruned completed tasks older than %s", cutoff.Format(time.RFC3339))
			return nil
		},
	}
}

// buildServicesTask constructs the services-collect scheduler task. The store
// is opened here and captured in the handler closure so it lives for the
// duration of the scheduler. Returns nil if the store cannot be initialised
// (logged as a warning; the rest of the agent continues normally).
func (mi *MainIntegration) buildServicesTask() *scheduler.Task {
	svcStore, err := store.NewServicesStore(mi.servicesDBPath())
	if err != nil {
		log.Printf("Warning: failed to open services store, services-collect disabled: %v", err)
		return nil
	}
	mi.servicesStore = svcStore

	return &scheduler.Task{
		Name:     "services-collect",
		Interval: mi.cfg.GetServicesUpdateInterval(),
		Enabled:  mi.cfg.ServicesSyncEnabled,
		Handler:  mi.servicesCollectHandler(svcStore),
	}
}

// servicesCollectHandler returns the TaskHandler for the services-collect task.
// Extracted to keep buildServicesTask under the cognitive complexity limit.
func (mi *MainIntegration) servicesCollectHandler(svcStore *store.ServicesStore) scheduler.TaskHandler {
	return func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
		if !cfg.ServicesSyncEnabled {
			return nil
		}
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping services-collect until session recovers")
			return nil
		}

		svc := servicessvc.NewServicesService()
		svc.SetSupabaseURL(cfg.SupabaseURL)
		svc.SetAPIKey(cfg.GetAccessToken())

		list := svc.GetServiceList()
		if len(list) == 0 {
			log.Printf("services-collect: no services found this cycle; skipping store")
			return nil
		}
		log.Printf("services-collect: %s services collected", sanitize.ForLog(fmt.Sprintf("%d", len(list))))

		if err := svcStore.Upsert(cfg.DeviceID, list); err != nil {
			return fmt.Errorf("services-collect: store upsert: %w", err)
		}

		activeKeys := make([]string, len(list))
		for i, s := range list {
			activeKeys[i] = s.Name + "\x00" + s.Source
		}
		if err := svcStore.DeleteNotIn(cfg.DeviceID, activeKeys); err != nil {
			log.Printf("services-collect: prune stale entries: %v", err)
		}

		send := func() error {
			_, err := svc.SendByRPCIfChanged(ctx, cfg.DeviceID, list, cfg)
			return err
		}
		if authSvc != nil {
			send = func() error {
				return authSvc.DoWithAuthRetry(ctx, cfg, func() error {
					_, err := svc.SendByRPCIfChanged(ctx, cfg.DeviceID, list, cfg)
					return err
				})
			}
		}
		return send()
	}
}

// softwareDBPath returns the path for the software SQLite catalog, placed in the
// same directory as config.json.
func (mi *MainIntegration) softwareDBPath() string {
	return filepath.Join(filepath.Dir(mi.cfg.Path), store.SoftwareDBName)
}

// softwareSyncHandler opens the local software catalog and returns a store-backed
// software-sync handler (collect → upsert → guarded prune → send). It returns nil
// when the store cannot be opened, in which case the default direct-send handler
// from CreateDefaultTasks is kept (logged; the agent continues normally).
func (mi *MainIntegration) softwareSyncHandler() scheduler.TaskHandler {
	if !mi.cfg.SoftwareSyncEnabled {
		// Keep the default no-op handler; don't create an unused catalog file.
		return nil
	}
	swStore, err := store.NewSoftwareStore(mi.softwareDBPath())
	if err != nil {
		log.Printf("Warning: failed to open software store, falling back to direct send: %v", err)
		return nil
	}
	mi.softwareStore = swStore

	return func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
		if !cfg.SoftwareSyncEnabled {
			return nil
		}
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping software-sync until session recovers")
			return nil
		}

		svc := swsvc.NewSoftwareService()
		svc.SetSupabaseURL(cfg.SupabaseURL)

		list, complete := svc.GetSoftwareListWithStatus()
		if len(list) == 0 {
			log.Printf("[software] no software found this cycle; skipping store and upload")
			return nil
		}

		// Load cached hashes from the local store so the enrichment pass can
		// skip re-hashing binaries that have not changed since the last cycle.
		// A cache-load failure is non-fatal: we fall back to an empty cache and
		// every binary with a FilePath will be hashed this cycle instead.
		hashCache, err := swStore.GetHashCache(cfg.DeviceID)
		if err != nil {
			log.Printf("[software] warning: could not load hash cache, re-hashing all entries: %v", err)
			hashCache = map[string]string{}
		}

		// Enrich the collected list with SHA-256 hashes. This is best-effort:
		// items without a FilePath or with unreadable binaries are left as-is
		// and never block the sync.
		list = swsvc.EnrichWithHash(list, hashCache, hashutil.ComputeFileHash)

		send := func() error {
			_, err := svc.SyncCatalog(ctx, swStore, cfg.DeviceID, list, complete, cfg)
			return err
		}
		if authSvc != nil {
			send = func() error {
				return authSvc.DoWithAuthRetry(ctx, cfg, func() error {
					_, err := svc.SyncCatalog(ctx, swStore, cfg.DeviceID, list, complete, cfg)
					return err
				})
			}
		}
		return send()
	}
}

// epmDBPath returns the path for the EPM policy/audit SQLite cache, placed in
// the same directory as config.json.
func (mi *MainIntegration) epmDBPath() string {
	return filepath.Join(filepath.Dir(mi.cfg.Path), store.EPMDBName)
}

// startEPM starts Endpoint Privilege Management when enabled. EPM defaults to
// disabled (cfg.EPMEnabled == false), in which case this is a no-op and the
// agent behaves exactly as it does today. Even when enabled, the enforcement
// transport only exists on Windows so far (see internal/epm/service_other.go
// for the stub on other platforms); any failure here is logged and
// non-fatal, matching how buildServicesTask/softwareSyncHandler degrade when
// their stores fail to open.
func (mi *MainIntegration) startEPM(ctx context.Context) {
	if !mi.cfg.EPMEnabled {
		return
	}

	epmStore, err := store.NewEPMStore(mi.epmDBPath())
	if err != nil {
		log.Printf("Warning: failed to open EPM store, EPM disabled for this run: %v", err)
		return
	}
	mi.epmStore = epmStore

	svc := epm.NewService(epmStore, epm.NewAuditor(epmStore))
	if err := svc.Start(ctx); err != nil {
		log.Printf("Warning: EPM service failed to start: %v", err)
		if runtime.GOOS != "windows" {
			log.Printf("Warning: EPM is only supported on Windows; Unix transport is not yet implemented")
		}
		return
	}
	mi.epmService = svc
	log.Printf("EPM enabled (policy sync interval: %v)", mi.cfg.GetEPMPolicySyncInterval())

	// Registering scheduler tasks here (rather than in configureScheduledTasks,
	// which runs earlier in Start) is safe: AddTask only needs to happen before
	// scheduler.Start, which is still a later step. It also keeps every piece of
	// EPM wiring in one place instead of splitting it across two methods.
	if err := mi.scheduler.AddTask(mi.buildEPMPolicySyncTask()); err != nil {
		log.Printf("Warning: failed to add epm-policy-sync scheduler task: %v", err)
	}
	if auditTask := mi.buildEPMAuditSyncTask(epmStore); auditTask != nil {
		if err := mi.scheduler.AddTask(auditTask); err != nil {
			log.Printf("Warning: failed to add epm-audit-sync scheduler task: %v", err)
		}
	}
}

// buildEPMPolicySyncTask periodically pulls and applies any pending
// epm-policy-sync task on its own cadence (cfg.GetEPMPolicySyncInterval()),
// independent of the general remote task-polling loop (which may run on a
// much longer interval, or be disabled entirely via cfg.EnableTaskPolling).
// It reuses the already-existing agent_get_tasks/agent_update_task RPCs (via
// taskstore.Client) and the already-registered "epm-policy-sync" native
// handler (internal/service/task/native) — no new backend endpoint is
// required. Running alongside the general TaskManager, when both are
// enabled, is expected and harmless: the native handler's UpsertRules/
// DeleteRulesNotIn are idempotent, so processing the same pending task twice
// converges to the same result.
func (mi *MainIntegration) buildEPMPolicySyncTask() *scheduler.Task {
	return &scheduler.Task{
		Name:     "epm-policy-sync",
		Interval: mi.cfg.GetEPMPolicySyncInterval(),
		Enabled:  true,
		Handler:  mi.epmPolicySyncHandler(),
	}
}

func (mi *MainIntegration) epmPolicySyncHandler() scheduler.TaskHandler {
	return func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
		if !cfg.EPMEnabled {
			return nil
		}
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping epm-policy-sync until session recovers")
			return nil
		}

		handler := native.Find("epm-policy-sync")
		if handler == nil {
			return fmt.Errorf("epm-policy-sync: native handler not registered")
		}

		client := taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken())

		var resp *taskstore.AgentTasksResponse
		var fetchErr error
		fetch := func() error {
			client.UpdateToken(cfg.GetAccessToken())
			resp, fetchErr = client.GetTasks(ctx)
			return fetchErr
		}
		if authSvc != nil {
			fetchErr = authSvc.DoWithAuthRetry(ctx, cfg, fetch)
		} else {
			fetchErr = fetch()
		}
		if fetchErr != nil {
			return fmt.Errorf("epm-policy-sync: fetch tasks: %w", fetchErr)
		}

		processed := 0
		for _, task := range resp.Tasks {
			if task.Slug != "epm-policy-sync" {
				continue
			}
			note, runErr := handler.Run(ctx, cfg, task)
			status := "success"
			if runErr != nil {
				status = "failed"
				note = runErr.Error()
				log.Printf("epm-policy-sync: task %s failed: %v", task.ID, runErr)
			}
			if updateErr := client.UpdateTask(ctx, task.ID, status, note); updateErr != nil {
				log.Printf("epm-policy-sync: report status for task %s: %v", task.ID, updateErr)
			}
			processed++
		}

		if processed > 0 {
			log.Printf("epm-policy-sync: processed %d pending policy-sync task(s)", processed)
		}
		return nil
	}
}

// buildEPMAuditSyncTask periodically drains EPM elevation-audit rows through
// the same upload pipeline used for OS-level audit logs (see
// internal/logging/epm_upload.go). Reuses the audit-log flush cadence
// (cfg.GetLogFlushInterval()) since this is conceptually the same kind of
// work. Returns nil (no task added) when audit logging itself is disabled —
// there is nowhere for EPM audit rows to go without the logging pipeline.
func (mi *MainIntegration) buildEPMAuditSyncTask(epmStore *store.EPMStore) *scheduler.Task {
	if mi.loggingService == nil {
		log.Printf("Warning: audit logs disabled, EPM elevation-audit upload will not run")
		return nil
	}
	return &scheduler.Task{
		Name:     "epm-audit-sync",
		Interval: mi.cfg.GetLogFlushInterval(),
		Enabled:  true,
		Handler:  mi.epmAuditSyncHandler(epmStore),
	}
}

func (mi *MainIntegration) epmAuditSyncHandler(epmStore *store.EPMStore) scheduler.TaskHandler {
	return func(ctx context.Context, cfg *config.Config, _ *authsvc.Service) error {
		if !cfg.EPMEnabled || mi.loggingService == nil {
			return nil
		}
		uploaded, err := mi.loggingService.UploadEPMAuditRows(ctx, epmStore)
		if err != nil {
			return fmt.Errorf("epm-audit-sync: %w", err)
		}
		if uploaded > 0 {
			log.Printf("epm-audit-sync: uploaded %d elevation audit record(s)", uploaded)
		}
		return nil
	}
}

// startLoggingService starts the audit log collection pipeline when enabled.
func (mi *MainIntegration) startLoggingService(ctx context.Context) error {
	if !mi.cfg.AuditLogsEnabled {
		log.Printf("Audit logs disabled in config (audit_logs_enabled=%s)",
			sanitize.ForLog(fmt.Sprintf("%v", mi.cfg.AuditLogsEnabled)))
		return nil
	}

	log.Printf("Audit logs enabled, starting logging service...")
	svc, err := logging.NewLoggingIntegration(mi.cfg)
	if err != nil {
		return fmt.Errorf("failed to create logging service: %w", err)
	}
	if mi.authSvc != nil {
		svc.SetAuth(mi.authSvc)
	}
	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("failed to start logging service: %w", err)
	}
	mi.loggingService = svc
	log.Printf("Audit log service started successfully")
	return nil
}

// startTaskManager starts the polling + execution task manager when task
// polling is enabled. Initialization failures are logged but non-fatal.
func (mi *MainIntegration) startTaskManager(ctx context.Context) {
	if !mi.cfg.EnableTaskPolling {
		return
	}

	tm, err := tasksvc.NewTaskManager(mi.cfg)
	if err != nil {
		log.Printf("Warning: Failed to initialize TaskManager: %v", err)
		return
	}

	// Set up token refresher for handling 401 errors
	if mi.authSvc != nil {
		tm.SetTokenRefresher(&authTokenRefresher{authSvc: mi.authSvc, cfg: mi.cfg})
	}

	mi.taskManager = tm
	go func() {
		if runErr := mi.taskManager.Run(ctx); runErr != nil {
			log.Printf("TaskManager stopped with error: %v", runErr)
		}
	}()
	log.Printf("TaskManager started (interval: %v)", mi.cfg.GetTaskPollingInterval())
}

// authTokenRefresher adapts authsvc.Service to tasksvc.TokenRefresher.
type authTokenRefresher struct {
	authSvc *authsvc.Service
	cfg     *config.Config
}

func (r *authTokenRefresher) RefreshToken(ctx context.Context) (string, error) {
	// Recover (refresh→agent-login, breaker-gated) rather than a bare refresh, so
	// task-polling shares the same recovery path and degraded state as every other
	// caller.
	if err := r.authSvc.Recover(ctx, r.cfg); err != nil {
		return "", err
	}
	return r.cfg.GetAccessToken(), nil
}

// Stop gracefully shuts down all services.
func (mi *MainIntegration) Stop() error {
	log.Printf("Stopping SentinelGo main integration...")

	// Stop scheduler first (this will stop all tasks)
	mi.scheduler.Stop()

	// Stop task manager
	if mi.taskManager != nil {
		if err := mi.taskManager.Close(); err != nil {
			log.Printf("Warning: Failed to close task manager: %v", err)
		}
	}

	// Stop audit log service
	if mi.loggingService != nil {
		if err := mi.loggingService.Stop(); err != nil {
			log.Printf("Warning: Failed to stop logging service: %v", err)
		}
	}

	// Close services store
	if mi.servicesStore != nil {
		if err := mi.servicesStore.Close(); err != nil {
			log.Printf("Warning: Failed to close services store: %v", err)
		}
	}

	// Close software store
	if mi.softwareStore != nil {
		if err := mi.softwareStore.Close(); err != nil {
			log.Printf("Warning: Failed to close software store: %v", err)
		}
	}

	// Stop EPM service
	if mi.epmService != nil {
		if err := mi.epmService.Stop(); err != nil {
			log.Printf("Warning: Failed to stop EPM service: %v", err)
		}
	}

	// Close EPM store
	if mi.epmStore != nil {
		if err := mi.epmStore.Close(); err != nil {
			log.Printf("Warning: Failed to close EPM store: %v", err)
		}
	}

	log.Printf("SentinelGo main integration stopped")
	return nil
}

// GetStatus returns status of all components.
func (mi *MainIntegration) GetStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// Scheduler status
	status["scheduler"] = mi.scheduler.GetTaskStatus()

	// Authentication status
	if mi.authSvc != nil {
		status["authentication"] = mi.authSvc.Status()
	}

	// Logging status
	if mi.loggingService != nil {
		status["logging"] = mi.loggingService.GetStatistics()
	}

	return status
}
