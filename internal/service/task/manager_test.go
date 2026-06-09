package task_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task"
)

func TestNewTaskManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-manager-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := loadTestConfig(t)
	cfg.TaskPollingInterval = config.Duration(1 * time.Second)
	cfg.TaskExecutionInterval = config.Duration(500 * time.Millisecond)
	cfg.TaskDBPath = filepath.Join(tempDir, "tasks.sqlite")

	taskManager, err := task.NewTaskManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create TaskManager: %v", err)
	}
	if taskManager == nil {
		t.Fatal("TaskManager is nil")
	}
	if err := taskManager.Close(); err != nil {
		t.Errorf("Failed to close TaskManager: %v", err)
	}
}

func TestTaskManagerSequentialWorkflow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-manager-sequential-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := &config.Config{
		EnableTaskPolling:     true,
		TaskPollingInterval:   config.Duration(100 * time.Millisecond),
		TaskExecutionInterval: config.Duration(50 * time.Millisecond),
		TaskDBPath:            filepath.Join(tempDir, "tasks.sqlite"),
	}

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
	case <-time.After(3 * time.Second):
		t.Error("TaskManager did not stop within expected time")
	}
}

func TestTaskManagerDefaultIntervals(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-manager-defaults-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	baseCfg := loadTestConfig(t)
	cfg := &config.Config{
		EnableTaskPolling:     true,
		TaskPollingInterval:   config.Duration(0),
		TaskExecutionInterval: config.Duration(0),
		SupabaseURL:           baseCfg.SupabaseURL,
		AccessToken:           baseCfg.AccessToken,
		AgentID:               baseCfg.AgentID,
		TaskDBPath:            filepath.Join(tempDir, "tasks.sqlite"),
	}

	taskManager, err := task.NewTaskManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create TaskManager: %v", err)
	}
	defer func() { _ = taskManager.Close() }()
	if taskManager == nil {
		t.Fatal("TaskManager is nil")
	}
}

func TestTaskManagerDisabledPolling(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-manager-disabled-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	baseCfg := loadTestConfig(t)
	cfg := &config.Config{
		EnableTaskPolling:     false,
		TaskPollingInterval:   config.Duration(1 * time.Second),
		TaskExecutionInterval: config.Duration(500 * time.Millisecond),
		SupabaseURL:           baseCfg.SupabaseURL,
		AccessToken:           baseCfg.AccessToken,
		AgentID:               baseCfg.AgentID,
		TaskDBPath:            filepath.Join(tempDir, "tasks.sqlite"),
	}

	taskManager, err := task.NewTaskManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create TaskManager: %v", err)
	}
	defer func() { _ = taskManager.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- taskManager.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("TaskManager failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("TaskManager did not stop within expected time")
	}
}

func TestTaskManagerErrorHandling(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "task-manager-error-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	baseCfg := loadTestConfig(t)
	cfg := &config.Config{
		EnableTaskPolling:     true,
		TaskPollingInterval:   config.Duration(1 * time.Second),
		TaskExecutionInterval: config.Duration(500 * time.Millisecond),
		SupabaseURL:           "",
		AccessToken:           baseCfg.AccessToken,
		AgentID:               baseCfg.AgentID,
		TaskDBPath:            filepath.Join(tempDir, "tasks.sqlite"),
	}

	taskManager, err := task.NewTaskManager(cfg)
	if err != nil {
		return // expected with invalid config
	}
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
	case <-time.After(2 * time.Second):
		t.Error("TaskManager did not stop within expected time")
	}
}
