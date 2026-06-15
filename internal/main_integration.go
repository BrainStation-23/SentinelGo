package internal

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	tasksvc "sentinelgo/internal/service/task"
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

	// 7. Start the task scheduler.
	if err := mi.scheduler.Start(mi.cfg, mi.authSvc); err != nil {
		emergencylog.Record("startup", "scheduler failed to start: %v", err)
		return fmt.Errorf("failed to start scheduler: %w", err)
	}

	log.Printf("SentinelGo main integration started successfully")
	return nil
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
		}
	}

	for _, task := range tasks {
		if err := mi.scheduler.AddTask(task); err != nil {
			return fmt.Errorf("failed to add task %s: %w", task.Name, err)
		}
	}

	log.Printf("Scheduler intervals: agent-info=%v, software-sync=%v, auto-update=%v, token-refresh=1m",
		mi.cfg.GetAgentInfoUpdateInterval(),
		mi.cfg.GetSoftwareInfoUpdateInterval(),
		mi.cfg.GetAutoUpdateInterval(),
	)
	return nil
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
