package internal

import (
	"context"
	"fmt"
	"log"

	"sentinelgo/internal/auth"
	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	tasksvc "sentinelgo/internal/service/task"
	"sentinelgo/internal/updater"
)

// MainIntegration orchestrates the agent's runtime components (auth, scheduler,
// logging, task manager) according to EXECUTION_FLOW.md. It wires together
// collaborators it is given and drives their startup/shutdown ordering; the
// concrete dependencies are supplied at construction time.
type MainIntegration struct {
	cfg            *config.Config
	scheduler      *scheduler.Scheduler
	enhancedAuth   *auth.EnhancedAuth
	authSvc        *authsvc.Service
	loggingService *logging.LoggingIntegration
	taskManager    *tasksvc.TaskManager
}

// NewMainIntegration wires the production dependencies and returns a ready
// MainIntegration. Use NewMainIntegrationWith to inject collaborators (e.g. in
// tests).
func NewMainIntegration(cfg *config.Config) *MainIntegration {
	return NewMainIntegrationWith(cfg, scheduler.NewScheduler(), auth.NewEnhancedAuth())
}

// NewMainIntegrationWith builds a MainIntegration from injected collaborators,
// allowing callers (and tests) to supply their own scheduler and auth. The
// auth service, logging service, and task manager are created during Start
// because they depend on the validated config and the run context.
func NewMainIntegrationWith(cfg *config.Config, sched *scheduler.Scheduler, enhancedAuth *auth.EnhancedAuth) *MainIntegration {
	return &MainIntegration{
		cfg:          cfg,
		scheduler:    sched,
		enhancedAuth: enhancedAuth,
	}
}

// Start initializes and starts all services according to the execution flow.
// It orchestrates a fixed sequence of init steps; each step is a focused method
// so the ordering is explicit and individually testable.
func (mi *MainIntegration) Start(ctx context.Context) error {
	mi.logStartup()

	// 1. Validate configuration before doing anything that depends on it.
	if err := mi.cfg.ValidateConfiguration(); err != nil {
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
		if err := updater.StartupUpdateCheck(ctx, mi.cfg, ""); err != nil {
			log.Printf("Startup update check failed: %v", err)
		}
	}()
}

// initAuth creates the auth service, initializes the session from stored
// tokens, and performs a preemptive token refresh. Failures are non-fatal:
// individual tasks handle token refresh on their own.
func (mi *MainIntegration) initAuth(ctx context.Context) {
	mi.authSvc = authsvc.NewService(mi.cfg.SupabaseURL, mi.cfg.AccessToken)

	if err := mi.authSvc.InitSession(mi.cfg); err != nil {
		log.Printf("Warning: Session init failed: %v", err)
	}

	if err := mi.validateAndRefreshTokens(ctx); err != nil {
		log.Printf("Warning: Initial token validation failed: %v", err)
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
	if err := r.authSvc.RefreshToken(ctx, r.cfg); err != nil {
		return "", err
	}
	return r.cfg.AccessToken, nil
}

// validateAndRefreshTokens performs preemptive token validation and refresh.
func (mi *MainIntegration) validateAndRefreshTokens(ctx context.Context) error {
	tokenRefreshFunc := func(ctx context.Context, cfg *config.Config) error {
		return mi.authSvc.RefreshToken(ctx, cfg)
	}
	return mi.enhancedAuth.ValidateAndRefreshTokens(ctx, mi.cfg, tokenRefreshFunc)
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
	status["authentication"] = mi.enhancedAuth.GetStats()

	// Logging status
	if mi.loggingService != nil {
		status["logging"] = mi.loggingService.GetStatistics()
	}

	return status
}
