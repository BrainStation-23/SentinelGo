package task_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/service/task"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestNewTaskExecutorService(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)
	if executorSvc == nil {
		t.Fatal("TaskExecutorService is nil")
	}
}

func TestTaskExecutorServiceExecutePendingTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-pending-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executorSvc.ExecutePendingTasks(ctx)
}

func TestTaskExecutorServiceRunExecutionLoop(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-loop-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	executorSvc.RunExecutionLoop(ctx)
}

func TestTaskExecutorServiceWithMockTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-mock-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "test.db")
	cfg := loadTestConfig(t)

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "mock-task-1", CommandID: "cmd-1", Slug: "mock-slug-1", Name: "Mock Task 1", Status: "assigned", Payload: map[string]interface{}{"test": "data"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/bin/echo"}}},
	}); err != nil {
		t.Fatalf("Failed to store mock tasks: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executorSvc.ExecutePendingTasks(ctx)
}

func TestTaskExecutorServiceErrorHandling(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-error-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "test.db")
	cfg := loadTestConfig(t)

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "error-task-1", CommandID: "cmd-error", Slug: "error-slug-1", Name: "Error Task 1", Status: "assigned", Payload: map[string]interface{}{"test": "data"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/nonexistent/path/to/script"}}},
	}); err != nil {
		t.Fatalf("Failed to store problematic tasks: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executorSvc.ExecutePendingTasks(ctx)
	t.Log("Error handling test completed successfully")
}

func TestTaskExecutorServiceConcurrentExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-concurrent-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	done := make(chan bool, 2)
	for g := 0; g < 2; g++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i := 0; i < 3; i++ {
				executorSvc.ExecutePendingTasks(ctx)
				time.Sleep(10 * time.Millisecond)
			}
			done <- true
		}()
	}
	<-done
	<-done
	t.Log("Concurrent execution test completed successfully")
}

func TestTaskExecutorServiceContextCancellation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-executor-cancel-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	executorSvc.ExecutePendingTasks(ctx)
	t.Log("Context cancellation test completed successfully")
}

func TestTaskExecutorServiceAgentUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping agent-update task execution (triggers real updater/network) in -short mode")
	}

	tempDir, err := os.MkdirTemp("", "task-executor-agent-update-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "test.db")
	cfg := loadTestConfig(t)

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, dbPath, &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	executorSvc := task.NewTaskExecutorService(cfg, pollingSvc)

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "agent-update-1", CommandID: "cmd-update", Slug: "agent-update", Name: "Agent Update", Status: "assigned", Payload: map[string]interface{}{}, Scripts: map[string]interface{}{}},
	}); err != nil {
		t.Fatalf("Failed to store agent-update task: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executorSvc.ExecutePendingTasks(ctx)
	t.Log("Agent-update task test completed successfully")
}
