package task_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestSequentialPollingThenExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-sequential-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	cfg.TaskPollingInterval = config.Duration(100 * time.Millisecond)
	cfg.TaskExecutionInterval = config.Duration(50 * time.Millisecond)
	cfg.TaskDBPath = filepath.Join(tempDir, "tasks.sqlite")

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, cfg.TaskDBPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	taskManager := task.NewTaskManagerWithPollingService(cfg, pollingSvc)
	defer func() { _ = taskManager.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- taskManager.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("TaskManager failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Error("TaskManager did not stop within expected time")
	}

	if _, err := os.Stat(cfg.TaskDBPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s", cfg.TaskDBPath)
	}
}

func TestTaskPersistenceBetweenPollingAndExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-persistence-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "persistence.db")
	cfg := loadTestConfig(t)

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}

	testTasks := []taskstore.Task{
		{ID: "persistence-task-1", CommandID: "cmd-1", Slug: "persistence-slug-1", Name: "Persistence Task 1", Status: "assigned", Payload: map[string]interface{}{"test": "persistence"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/bin/echo"}}},
	}

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks(testTasks); err != nil {
		t.Fatalf("Failed to store test tasks: %v", err)
	}

	_ = pollingSvc.Close()

	pollingSvc2, err := task.NewTaskPollingService(cfg, dbPath)
	if err != nil {
		t.Fatalf("Failed to create second TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc2.Close() }()

	tasks, err := pollingSvc2.GetLocalTasks()
	if err != nil {
		t.Errorf("Failed to get local tasks from second service: %v", err)
	}
	if len(tasks) != len(testTasks) {
		t.Errorf("Expected %d tasks after restart, got %d", len(testTasks), len(tasks))
	}
	for i, tk := range tasks {
		if tk.ID != testTasks[i].ID {
			t.Errorf("Expected task ID %s, got %s", testTasks[i].ID, tk.ID)
		}
		if tk.Status != "assigned" {
			t.Errorf("Expected status 'assigned', got %s", tk.Status)
		}
	}
}

func TestConcurrentPollingAndExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-concurrent-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "concurrent.db")
	cfg := loadTestConfig(t)

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 5; i++ {
			tasks, err := pollingSvc.GetLocalTasks()
			if err != nil {
				t.Errorf("Failed to get local tasks in polling goroutine: %v", err)
			}
			t.Logf("Polling goroutine %d: Found %d tasks", i, len(tasks))
			time.Sleep(50 * time.Millisecond)
		}
		done <- true
	}()

	go func() {
		ctx := context.Background()
		for i := 0; i < 5; i++ {
			executorSvc.ExecutePendingTasks(ctx)
			t.Logf("Execution goroutine %d: Completed execution loop", i)
			time.Sleep(50 * time.Millisecond)
		}
		done <- true
	}()

	<-done
	<-done
	t.Log("Concurrent polling and execution test completed successfully")
}

func TestTaskManagerWithRealDatabaseOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-real-db-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "real.db")
	cfg := loadTestConfig(t)
	cfg.TaskPollingInterval = config.Duration(200 * time.Millisecond)
	cfg.TaskExecutionInterval = config.Duration(100 * time.Millisecond)
	cfg.TaskDBPath = dbPath

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	taskManager := task.NewTaskManagerWithPollingService(cfg, pollingSvc)
	defer func() { _ = taskManager.Close() }()

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "real-db-task-1", CommandID: "cmd-1", Slug: "real-db-slug-1", Name: "Real DB Task 1", Status: "assigned", Payload: map[string]interface{}{"test": "real-db"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/bin/echo"}}},
	}); err != nil {
		t.Fatalf("Failed to store test tasks: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- taskManager.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("TaskManager failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Error("TaskManager did not stop within expected time")
	}

	finalTasks, err := ts.GetAssignedTasks()
	if err != nil {
		t.Errorf("Failed to get final tasks: %v", err)
	}
	t.Logf("Found %d tasks in database after TaskManager run", len(finalTasks))
}

func TestTaskManagerErrorRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-error-recovery-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	cfg.TaskPollingInterval = config.Duration(100 * time.Millisecond)
	cfg.TaskExecutionInterval = config.Duration(50 * time.Millisecond)
	cfg.TaskDBPath = filepath.Join(tempDir, "tasks.sqlite")

	errClient := &mockTaskClient{
		getErr:    fmt.Errorf("simulated network error"),
		updateErr: fmt.Errorf("simulated network error"),
	}
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, cfg.TaskDBPath, errClient)
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	taskManager := task.NewTaskManagerWithPollingService(cfg, pollingSvc)
	defer func() { _ = taskManager.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- taskManager.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Logf("TaskManager completed with error (expected): %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Error("TaskManager did not stop within expected time")
	}

	if _, err := os.Stat(cfg.TaskDBPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s despite errors", cfg.TaskDBPath)
	}
}

func TestTaskManagerMultipleCycles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-integration-cycles-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	cfg.TaskPollingInterval = config.Duration(50 * time.Millisecond)
	cfg.TaskExecutionInterval = config.Duration(25 * time.Millisecond)
	cfg.TaskDBPath = filepath.Join(tempDir, "tasks.sqlite")

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, cfg.TaskDBPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	taskManager := task.NewTaskManagerWithPollingService(cfg, pollingSvc)
	defer func() { _ = taskManager.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- taskManager.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("TaskManager failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Error("TaskManager did not stop within expected time")
	}

	if _, err := os.Stat(cfg.TaskDBPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s", cfg.TaskDBPath)
	}
	t.Log("Multiple cycles test completed successfully")
}
