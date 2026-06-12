package task_test

// Tests for handleRestartContext and getTasksWithRetry edge cases.
// Uses the existing task_test package and mock helpers from helpers_test.go.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/service/task"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestHandleRestartContext_NoFile_NoOp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tasks.db")

	cfg := loadTestConfig(t)
	cfg.Path = filepath.Join(dir, "config.json")

	svc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()

	// PollAndStoreTasks calls handleRestartContext internally.
	// With no restart context file, it should proceed without error.
	if err := svc.PollAndStoreTasks(context.Background()); err != nil {
		t.Fatalf("PollAndStoreTasks with no restart context: %v", err)
	}
}

func TestHandleRestartContext_ValidFile_MarksTaskSuccess(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tasks.db")

	cfg := loadTestConfig(t)
	cfg.Path = filepath.Join(dir, "config.json")

	// Insert a task in 'executing' state — simulating a task that triggered the restart.
	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("NewTaskStore: %v", err)
	}
	taskID := "restart-task-001"
	if err := ts.StoreTasks([]taskstore.Task{
		{
			ID:      taskID,
			Slug:    "agent-update",
			Name:    "Agent Update",
			Status:  "executing",
			Payload: map[string]interface{}{},
			Scripts: map[string]interface{}{},
		},
	}); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}
	_ = ts.Close()

	// Write the restart context file that the restarted agent would have written.
	ctxPath := restartctx.PathFor(cfg.Path)
	if err := restartctx.Write(ctxPath, restartctx.Context{
		TaskID: taskID,
		Reason: "agent-update",
	}); err != nil {
		t.Fatalf("Write restart context: %v", err)
	}

	svc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()

	if err := svc.PollAndStoreTasks(context.Background()); err != nil {
		t.Fatalf("PollAndStoreTasks: %v", err)
	}

	// Context file must be consumed.
	if _, statErr := os.Stat(ctxPath); !os.IsNotExist(statErr) {
		t.Error("restart context file should be deleted after being processed")
	}

	// The task should no longer appear in 'assigned' (it was moved to 'success').
	assigned, err := svc.GetLocalTasks()
	if err != nil {
		t.Fatalf("GetLocalTasks: %v", err)
	}
	for _, tk := range assigned {
		if tk.ID == taskID {
			t.Errorf("task %s should not be 'assigned' after restart context was processed", taskID)
		}
	}
}

func TestHandleRestartContext_FileAlwaysDeletedAfterProcessing(t *testing.T) {
	dir := t.TempDir()
	cfg := loadTestConfig(t)
	cfg.Path = filepath.Join(dir, "config.json")

	ctxPath := restartctx.PathFor(cfg.Path)
	if err := restartctx.Write(ctxPath, restartctx.Context{
		TaskID: "any-task",
		Reason: "device-reboot",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	svc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(dir, "tasks.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()

	_ = svc.PollAndStoreTasks(context.Background())

	if _, err := os.Stat(ctxPath); !os.IsNotExist(err) {
		t.Error("restart context file should always be deleted after PollAndStoreTasks, even if the task is unknown")
	}
}

func TestGetTasksWithRetry_Non401_NoRefresh(t *testing.T) {
	dir := t.TempDir()
	cfg := loadTestConfig(t)

	networkErr := errors.New("dial tcp: connection refused")
	client := &mockTaskClient{getErr: networkErr}
	refresher := &mockTokenRefresher{}

	svc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(dir, "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	err = svc.PollAndStoreTasks(context.Background())
	if err == nil {
		t.Fatal("expected error from network failure")
	}
	if refresher.called {
		t.Error("token refresher must not be called for non-401 errors")
	}
}

func TestGetTasksWithRetry_401_CallsRefresher(t *testing.T) {
	dir := t.TempDir()
	cfg := loadTestConfig(t)

	// Client always returns 401 (even after a refresh the mock is stateless).
	client := &mockTaskClient{getErr: fmt.Errorf("authentication failed: status 401")}
	refresher := &mockTokenRefresher{token: "new-token"}

	svc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(dir, "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	_ = svc.PollAndStoreTasks(context.Background())

	if !refresher.called {
		t.Error("token refresher must be called on 401 error")
	}
}

func TestGetTasksWithRetry_401_RefreshFails_ReturnsOriginalError(t *testing.T) {
	dir := t.TempDir()
	cfg := loadTestConfig(t)

	client := &mockTaskClient{getErr: fmt.Errorf("authentication failed: status 401")}
	refresher := &mockTokenRefresher{err: errors.New("refresh server down")}

	svc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(dir, "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	err = svc.PollAndStoreTasks(context.Background())
	if err == nil {
		t.Fatal("expected error when refresh fails")
	}
}

func TestGetTasksWithRetry_NoRefresherSet_Returns401Error(t *testing.T) {
	dir := t.TempDir()
	cfg := loadTestConfig(t)

	client := &mockTaskClient{getErr: fmt.Errorf("authentication failed: status 401")}
	svc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(dir, "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	// No tokenRefresher set — must handle gracefully.

	err = svc.PollAndStoreTasks(context.Background())
	if err == nil {
		t.Fatal("expected error when 401 and no refresher configured")
	}
}
