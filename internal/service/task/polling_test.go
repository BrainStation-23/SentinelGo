package task_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/service/task"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestNewTaskPollingService(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), &mockTaskClient{})
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	if pollingSvc == nil {
		t.Fatal("TaskPollingService is nil")
	}
	if err := pollingSvc.Close(); err != nil {
		t.Errorf("Failed to close TaskPollingService: %v", err)
	}
}

func TestTaskPollingServiceGetLocalTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-local-test")
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

	tasks, err := pollingSvc.GetLocalTasks()
	if err != nil {
		t.Fatalf("Failed to get local tasks: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("Expected 0 local tasks, got %d", len(tasks))
	}
}

func TestTaskPollingServiceTokenRefreshOn401(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-401-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)

	// Mock client that returns 401
	mockClient := &mockTaskClient{
		getErr: fmt.Errorf("authentication failed: status 401"),
	}

	pollingSvc, err := task.NewTaskPollingServiceWithClient(cfg, filepath.Join(tempDir, "test.db"), mockClient)
	if err != nil {
		t.Fatalf("Failed to create TaskPollingService: %v", err)
	}
	defer func() { _ = pollingSvc.Close() }()

	// Set up token refresher that returns a new token
	mockRefresher := &mockTokenRefresher{
		token: "new-access-token",
		err:   nil,
	}

	pollingSvc.SetTokenRefresher(mockRefresher)

	// This should trigger token refresh
	ctx := context.Background()
	err = pollingSvc.PollAndStoreTasks(ctx)

	// Should fail (since mockClient still returns 401 after refresh)
	if err == nil {
		t.Fatal("Expected error after token refresh (mock still returns 401)")
	}

	// But token refresh should have been called
	if !mockRefresher.called {
		t.Error("Token refresh was not called on 401 error")
	}
}

func TestTaskPollingServiceStoreTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-store-test")
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

	testTasks := []taskstore.Task{
		{ID: "test-task-1", CommandID: "cmd-1", Slug: "test-slug-1", Name: "Test Task 1", Status: "assigned", Payload: map[string]interface{}{"key": "value1"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script1.sh"}}},
		{ID: "test-task-2", CommandID: "cmd-2", Slug: "test-slug-2", Name: "Test Task 2", Status: "assigned", Payload: map[string]interface{}{"key": "value2"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script2.sh"}}},
	}

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks(testTasks); err != nil {
		t.Errorf("Failed to store tasks: %v", err)
	}

	tasks, err := pollingSvc.GetLocalTasks()
	if err != nil {
		t.Errorf("Failed to get local tasks: %v", err)
	}
	if len(tasks) != len(testTasks) {
		t.Errorf("Expected %d tasks, got %d", len(testTasks), len(tasks))
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

func TestTaskPollingServiceUpdateTaskStatus(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-update-test")
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

	testTask := taskstore.Task{ID: "test-task-update", CommandID: "cmd-update", Slug: "test-slug-update", Name: "Test Task Update", Status: "assigned", Payload: map[string]interface{}{"key": "value"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script.sh"}}}

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{testTask}); err != nil {
		t.Fatalf("Failed to store test task: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pollingSvc.ReportTaskStatus(ctx, testTask.ID, "success", "Task completed successfully"); err != nil {
		t.Errorf("Failed to update task status: %v", err)
	}

	assignedTasks, err := pollingSvc.GetLocalTasks()
	if err != nil {
		t.Errorf("Failed to get local tasks: %v", err)
	}
	if len(assignedTasks) != 0 {
		t.Errorf("Expected 0 assigned tasks after status update, got %d", len(assignedTasks))
	}
}

func TestTaskPollingServiceResetFailedTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-reset-test")
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

	testTask := taskstore.Task{ID: "test-task-failed", CommandID: "cmd-failed", Slug: "test-slug-failed", Name: "Test Task Failed", Status: "failed", Payload: map[string]interface{}{"key": "value"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script.sh"}}}

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{testTask}); err != nil {
		t.Fatalf("Failed to store test task: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	resetCount, err := ts.ResetOldFailedTasks(1 * time.Millisecond)
	if err != nil {
		t.Errorf("Failed to reset failed tasks: %v", err)
	}
	if resetCount != 1 {
		t.Errorf("Expected to reset 1 task, reset %d", resetCount)
	}

	tasks, err := pollingSvc.GetLocalTasks()
	if err != nil {
		t.Errorf("Failed to get local tasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Errorf("Expected 1 task after reset, got %d", len(tasks))
	}
	if tasks[0].Status != "assigned" {
		t.Errorf("Expected status 'assigned' after reset, got %s", tasks[0].Status)
	}
}

func TestTaskPollingServiceSyncPendingTasks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-sync-test")
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

	testTask := taskstore.Task{ID: "550e8400-e29b-41d4-a716-446655440000", CommandID: "cmd-completed", Slug: "test-slug-completed", Name: "Test Task Completed", Status: "success", Payload: map[string]interface{}{"key": "value"}, Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script.sh"}}}

	ts, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = ts.Close() }()

	if err := ts.StoreTasks([]taskstore.Task{testTask}); err != nil {
		t.Fatalf("Failed to store test task: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = pollingSvc.SyncPendingTasks(ctx)
}

func TestTaskPollingServiceErrorHandling(t *testing.T) {
	cfg := loadTestConfig(t)
	_, err := task.NewTaskPollingServiceWithClient(cfg, "/nonexistent/directory/test.db", &mockTaskClient{})
	if err == nil {
		t.Error("Expected error when creating TaskPollingService with invalid path")
	}
}

func TestTaskPollingServiceConcurrentAccess(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-polling-concurrent-test")
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

	done := make(chan bool, 2)

	go func() {
		ts, err := store.NewTaskStore(dbPath)
		if err != nil {
			t.Errorf("Failed to create store in goroutine 1: %v", err)
			done <- true
			return
		}
		defer func() { _ = ts.Close() }()

		for i := 0; i < 5; i++ {
			tk := taskstore.Task{
				ID:      fmt.Sprintf("concurrent-task-1-%d", i),
				Slug:    fmt.Sprintf("slug-1-%d", i),
				Name:    fmt.Sprintf("Concurrent Task 1-%d", i),
				Status:  "assigned",
				Payload: map[string]interface{}{"index": i},
				Scripts: map[string]interface{}{"linux": map[string]string{"path": "/test/script.sh"}},
			}
			if err := ts.StoreTasks([]taskstore.Task{tk}); err != nil {
				t.Errorf("Failed to store task in goroutine 1: %v", err)
			}
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 5; i++ {
			if _, err := pollingSvc.GetLocalTasks(); err != nil {
				t.Errorf("Failed to get local tasks in goroutine 2: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	<-done
	<-done

	tasks, err := pollingSvc.GetLocalTasks()
	if err != nil {
		t.Errorf("Failed to get final local tasks: %v", err)
	}
	if len(tasks) != 5 {
		t.Errorf("Expected 5 tasks, got %d", len(tasks))
	}
}
