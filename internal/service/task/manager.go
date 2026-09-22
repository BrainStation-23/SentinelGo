package task

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/paths"
)

// TokenRefresher is the interface for refreshing authentication tokens.
type TokenRefresher interface {
	RefreshToken(ctx context.Context) (string, error)
}

// TaskManager handles integrated task polling and execution.
type TaskManager struct {
	cfg           *config.Config
	pollingSvc    *TaskPollingService
	executorSvc   *TaskExecutorService
	dbPath        string
	lastTaskCount int
	runningTasks  map[string]bool
}

// NewTaskManager creates a new integrated task manager.
func NewTaskManager(cfg *config.Config) (*TaskManager, error) {
	var dbPath string
	if cfg.TaskDBPath != "" {
		dbPath = cfg.TaskDBPath
	} else {
		dbPath = paths.TaskDBPath()
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create task storage directory %s: %w",
				filepath.Dir(dbPath), err)
		}
	}
	log.Printf("TaskManager: Using database path: %s", dbPath)

	pollingSvc, err := NewTaskPollingService(cfg, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create task polling service: %w", err)
	}

	executorSvc := NewTaskExecutorService(cfg, pollingSvc)

	return &TaskManager{
		cfg:          cfg,
		pollingSvc:   pollingSvc,
		executorSvc:  executorSvc,
		dbPath:       dbPath,
		runningTasks: make(map[string]bool),
	}, nil
}

// SetTokenRefresher sets the token refresher for the polling service.
func (tm *TaskManager) SetTokenRefresher(refresher TokenRefresher) {
	if tm.pollingSvc != nil {
		tm.pollingSvc.SetTokenRefresher(refresher)
	}
}

// NewTaskManagerWithPollingService creates a TaskManager with an existing polling
// service. Intended for use in tests to inject a mock-backed polling service.
func NewTaskManagerWithPollingService(cfg *config.Config, pollingSvc *TaskPollingService) *TaskManager {
	return &TaskManager{
		cfg:          cfg,
		pollingSvc:   pollingSvc,
		executorSvc:  NewTaskExecutorService(cfg, pollingSvc),
		dbPath:       cfg.TaskDBPath,
		runningTasks: make(map[string]bool),
	}
}

// Run starts the integrated task polling and execution service.
func (tm *TaskManager) Run(ctx context.Context) error {
	log.Printf("TaskManager: Starting integrated task service")
	log.Printf("TaskManager: Task polling enabled: %v", tm.cfg.EnableTaskPolling)
	log.Printf("TaskManager: Polling interval: %v", time.Duration(tm.cfg.TaskPollingInterval))
	log.Printf("TaskManager: Execution interval: %v", time.Duration(tm.cfg.TaskExecutionInterval))

	if tm.cfg.EnableTaskPolling {
		tm.runSequentialTaskLoop(ctx)
	}

	<-ctx.Done()
	return tm.Close()
}

func (tm *TaskManager) runSequentialTaskLoop(ctx context.Context) {
	pollingInterval := time.Duration(tm.cfg.TaskPollingInterval)
	if pollingInterval <= 0 {
		pollingInterval = 5 * time.Minute
		log.Printf("TaskManager: Using default polling interval: %v", pollingInterval)
	}

	executionInterval := time.Duration(tm.cfg.TaskExecutionInterval)
	if executionInterval <= 0 {
		executionInterval = 30 * time.Second
		log.Printf("TaskManager: Using default execution interval: %v", executionInterval)
	}

	mainInterval := pollingInterval
	log.Printf("TaskManager: Starting sequential task loop with interval: %v", mainInterval)

	go tm.executorSvc.RunWatchdog(ctx)

	log.Printf("TaskManager: Initial polling...")
	tm.pollTasks(ctx)

	log.Printf("TaskManager: Initial execution...")
	tm.executeTasks(ctx)

	ticker := time.NewTicker(mainInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("TaskManager: Polling for tasks...")
			tm.pollTasks(ctx)

			log.Printf("TaskManager: Executing tasks...")
			tm.executeTasks(ctx)
		}
	}
}

func (tm *TaskManager) pollTasks(ctx context.Context) {
	log.Printf("TaskManager: Polling for tasks...")

	if err := tm.pollingSvc.PollAndStoreTasks(ctx); err != nil {
		log.Printf("TaskManager: Error polling tasks: %v", err)
		return
	}

	tasks, err := tm.pollingSvc.GetLocalTasks()
	if err != nil {
		log.Printf("TaskManager: Error getting local tasks: %v", err)
		return
	}

	currentTaskCount := len(tasks)
	if currentTaskCount > tm.lastTaskCount {
		log.Printf("TaskManager: New tasks detected! (%d -> %d)", tm.lastTaskCount, currentTaskCount)
		tm.lastTaskCount = currentTaskCount
	} else {
		log.Printf("TaskManager: No new tasks found (%d total)", currentTaskCount)
	}
}

func (tm *TaskManager) executeTasks(ctx context.Context) {
	log.Printf("TaskManager: Executing pending tasks...")
	tm.executorSvc.ExecutePendingTasks(ctx)
}

// Close closes the task manager and its services.
func (tm *TaskManager) Close() error {
	log.Printf("TaskManager: Closing integrated task service")

	var err error
	if tm.pollingSvc != nil {
		if closeErr := tm.pollingSvc.Close(); closeErr != nil {
			log.Printf("TaskManager: Error closing polling service: %v", closeErr)
			err = closeErr
		}
	}

	return err
}
