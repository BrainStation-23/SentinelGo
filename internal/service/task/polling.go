package task

import (
	"context"
	"fmt"
	"log"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/network"
	"sentinelgo/internal/service/auth"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// TaskClient is the interface for remote task RPC operations.
type TaskClient interface {
	GetTasks(ctx context.Context) (*taskstore.AgentTasksResponse, error)
	UpdateTask(ctx context.Context, taskID, status, note string) error
	UpdateToken(token string)
}

// internetChecker gates all outbound calls behind a connectivity check.
type internetChecker interface {
	CheckInternet(ctx context.Context) error
}

// noopConnectivity always reports connectivity as available. Used in tests.
type noopConnectivity struct{}

func (noopConnectivity) CheckInternet(_ context.Context) error { return nil }

// TaskPollingService handles task polling and storage.
type TaskPollingService struct {
	client              TaskClient
	store               *store.TaskStore
	cfg                 *config.Config
	connectivityChecker internetChecker
	tokenRefresher      TokenRefresher
}

// NewTaskPollingService creates a new task polling service.
func NewTaskPollingService(cfg *config.Config, dbPath string) (*TaskPollingService, error) {
	client := taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken())

	taskStore, err := store.NewTaskStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("create task store: %w", err)
	}

	connectivityChecker := network.NewConnectivityChecker().
		WithCheckURL(cfg.SupabaseURL).
		WithTimeout(5 * time.Second)

	return &TaskPollingService{
		client:              client,
		store:               taskStore,
		cfg:                 cfg,
		connectivityChecker: connectivityChecker,
		tokenRefresher:      nil, // Set via SetTokenRefresher
	}, nil
}

// NewTaskPollingServiceWithClient creates a TaskPollingService with an injectable
// client and bypasses connectivity checks. Intended for use in tests.
func NewTaskPollingServiceWithClient(cfg *config.Config, dbPath string, client TaskClient) (*TaskPollingService, error) {
	taskStore, err := store.NewTaskStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("create task store: %w", err)
	}
	return &TaskPollingService{
		client:              client,
		store:               taskStore,
		cfg:                 cfg,
		connectivityChecker: noopConnectivity{},
	}, nil
}

// UpdateToken refreshes the access token in the RPC client.
func (s *TaskPollingService) UpdateToken(token string) {
	s.client.UpdateToken(token)
}

// SetTokenRefresher sets the token refresher for handling 401 errors.
func (s *TaskPollingService) SetTokenRefresher(refresher TokenRefresher) {
	s.tokenRefresher = refresher
}

// MarkTaskExecuting transitions a task to 'executing' before the script runs.
// See store.TaskStore.MarkTaskExecuting for the safety rationale.
func (s *TaskPollingService) MarkTaskExecuting(taskID string) error {
	return s.store.MarkTaskExecuting(taskID)
}

// handleRestartContext reads pending_restart.json (if present) and marks the
// triggering task as success before ResetInterruptedTasks can mark it failed.
// The file is written by the agent-update and reboot-device handlers immediately
// before os.Exit() / reboot, so its presence on startup means the operation
// completed — the binary was replaced or the device came back up.
func (s *TaskPollingService) handleRestartContext() {
	if s.cfg == nil || s.cfg.Path == "" {
		return
	}

	rc, err := restartctx.ReadAndClear(restartctx.PathFor(s.cfg.Path))
	if err != nil {
		log.Printf("TaskPolling: failed to read restart context: %v", err)
		return
	}
	if rc == nil {
		return
	}

	var msg string
	switch rc.Reason {
	case "agent-update":
		msg = fmt.Sprintf("Agent updated from %s to %s and restarted successfully.",
			rc.FromVersion, config.Version)
	case "device-reboot":
		msg = "Device rebooted successfully. Agent is back online."
	default:
		msg = fmt.Sprintf("Agent restarted (reason: %s).", rc.Reason)
	}

	// isSynced=false so SyncPendingTasks (called later in PollAndStoreTasks)
	// will push the result to the server on the next poll.
	if err := s.store.UpdateTaskStatus(rc.TaskID, "success", msg, false); err != nil {
		log.Printf("TaskPolling: failed to mark restart-context task %s as success: %v", rc.TaskID, err)
		return
	}
	log.Printf("TaskPolling: task %s marked success (restart reason: %s)", rc.TaskID, rc.Reason)
}

// PollAndStoreTasks fetches tasks from RPC and stores them in SQLite.
func (s *TaskPollingService) PollAndStoreTasks(ctx context.Context) error {
	// Resolve any task that intentionally triggered this restart before the
	// generic interrupted-task cleanup runs below.
	s.handleRestartContext()

	// Clean up tasks that were mid-execution when the agent last died. They are
	// marked 'failed (interrupted)' with is_synced=0 so SyncPendingTasks below
	// will report them to the server. attempt_count is maxed so they are never
	// automatically retried (re-running a reboot task would loop forever).
	if n, err := s.store.ResetInterruptedTasks(); err != nil {
		log.Printf("TaskPolling: failed to reset interrupted tasks: %v", err)
	} else if n > 0 {
		log.Printf("TaskPolling: marked %d interrupted task(s) as failed (were 'executing' at restart)", n)
	}

	if retryable, err := s.store.GetRetryableTasks(5 * time.Minute); err != nil {
		log.Printf("TaskPolling: Failed to get retryable tasks: %v", err)
	} else {
		for _, t := range retryable {
			note := fmt.Sprintf("Attempt %d of %d failed; retrying.",
				t.AttemptCount+1, store.MaxRetryAttempts+1)
			if err := s.client.UpdateTask(ctx, t.ID, "retrying", note); err != nil {
				log.Printf("TaskPolling: Failed to report retrying status for task %s: %v", t.ID, err)
			}
		}
	}

	if resetCount, err := s.store.ResetOldFailedTasks(5 * time.Minute); err != nil {
		log.Printf("TaskPolling: Failed to reset old failed tasks: %v", err)
	} else if resetCount > 0 {
		log.Printf("TaskPolling: Reset %d failed tasks to 'assigned' for retry", resetCount)
	}

	if err := s.connectivityChecker.CheckInternet(ctx); err != nil {
		log.Printf("TaskPolling: Internet connectivity check failed: %v", err)
		return fmt.Errorf("internet connectivity check failed: %w", err)
	}

	log.Printf("TaskPolling: Internet connectivity verified, proceeding with task polling")

	if err := s.SyncPendingTasks(ctx); err != nil {
		log.Printf("TaskPolling: Sync results failed: %v", err)
	}

	resp, err := s.getTasksWithRetry(ctx)
	if err != nil {
		return fmt.Errorf("get tasks: %w", err)
	}

	log.Printf("TaskPolling: Successfully polled %d tasks from agent_get_tasks", len(resp.Tasks))

	if len(resp.Tasks) > 0 {
		if err := s.store.StoreTasks(resp.Tasks); err != nil {
			return fmt.Errorf("store tasks: %w", err)
		}
		log.Printf("TaskPolling: Stored %d tasks in local database", len(resp.Tasks))
	}

	return nil
}

// getTasksWithRetry attempts to get tasks with a single retry on 401.
func (s *TaskPollingService) getTasksWithRetry(ctx context.Context) (*taskstore.AgentTasksResponse, error) {
	resp, err := s.client.GetTasks(ctx)
	if err == nil {
		return resp, nil
	}

	// Use the shared classifier rather than matching one literal string. The
	// taskstore client is only one of three layers that can surface a 401, and
	// each phrases it differently; a local match here silently stops recovering
	// the moment that one wording changes.
	if s.tokenRefresher != nil && auth.IsUnauthorized(err) {
		log.Printf("TaskPolling: Got 401, attempting token refresh...")
		newToken, refreshErr := s.tokenRefresher.RefreshToken(ctx)
		if refreshErr != nil {
			log.Printf("TaskPolling: Token refresh failed: %v", refreshErr)
			return nil, err // Return original error
		}
		log.Printf("TaskPolling: Token refresh successful, updating client and retrying...")
		s.client.UpdateToken(newToken)
		return s.client.GetTasks(ctx)
	}

	return nil, err
}

// GetLocalTasks returns tasks stored locally (for crash recovery).
func (s *TaskPollingService) GetLocalTasks() ([]taskstore.Task, error) {
	return s.store.GetAssignedTasks()
}

// ReportTaskStatus updates task status via RPC and local storage.
func (s *TaskPollingService) ReportTaskStatus(ctx context.Context, taskID, status, note string) error {
	isSynced := false

	err := s.client.UpdateTask(ctx, taskID, status, note)
	if err == nil {
		isSynced = true
	} else {
		log.Printf("TaskPolling: Network update failed for task %s (status: %s). Result stored locally for retry.", taskID, status)
	}

	if err := s.store.UpdateTaskStatus(taskID, status, note, isSynced); err != nil {
		return fmt.Errorf("update task in store: %w", err)
	}

	return nil
}

// SyncPendingTasks pushes locally completed tasks that haven't been reported yet.
func (s *TaskPollingService) SyncPendingTasks(ctx context.Context) error {
	tasks, err := s.store.GetUnsyncedTasks()
	if err != nil {
		return fmt.Errorf("get unsynced tasks: %w", err)
	}

	if len(tasks) == 0 {
		return nil
	}

	log.Printf("TaskPolling: Found %d unsynced task results. Attempting sync...", len(tasks))

	for _, task := range tasks {
		log.Printf("TaskPolling: Syncing task %s...", task.ID)
		if err := s.client.UpdateTask(ctx, task.ID, task.Status, task.Note); err != nil {
			log.Printf("TaskPolling: Failed to sync task %s: %v", task.ID, err)
			continue
		}
		if err := s.store.MarkTaskSynced(task.ID); err != nil {
			log.Printf("TaskPolling: Failed to mark task %s as synced locally: %v", task.ID, err)
		}
	}

	return nil
}

// CleanupCompletedTasks removes old completed tasks from local storage.
func (s *TaskPollingService) CleanupCompletedTasks(olderThan time.Time) error {
	return s.store.ClearCompletedTasks(olderThan)
}

// Close closes the task store.
func (s *TaskPollingService) Close() error {
	return s.store.Close()
}
