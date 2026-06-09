package scheduler_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

func TestNewScheduler(t *testing.T) {
	s := scheduler.NewScheduler()
	if s == nil {
		t.Fatal("NewScheduler() returned nil")
	}
}

func TestScheduler_AddTask(t *testing.T) {
	s := scheduler.NewScheduler()

	task := &scheduler.Task{
		Name:     "test-task",
		Interval: 5 * time.Minute,
		Handler:  func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error { return nil },
		Enabled:  true,
	}

	err := s.AddTask(task)
	if err != nil {
		t.Errorf("AddTask() failed: %v", err)
	}

	// Adding same task again should fail
	err = s.AddTask(task)
	if err == nil {
		t.Error("AddTask() should fail when adding duplicate task")
	}
}

func TestScheduler_AddTask_WithDependencies(t *testing.T) {
	s := scheduler.NewScheduler()

	task1 := &scheduler.Task{
		Name:     "task1",
		Interval: 5 * time.Minute,
		Handler:  func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error { return nil },
		Enabled:  true,
	}

	task2 := &scheduler.Task{
		Name:         "task2",
		Interval:     5 * time.Minute,
		Dependencies: []string{"task1"},
		Handler:      func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error { return nil },
		Enabled:      true,
	}

	// Add task with non-existent dependency should fail
	err := s.AddTask(task2)
	if err == nil {
		t.Error("AddTask() should fail when dependency doesn't exist")
	}

	// Add dependency first
	err = s.AddTask(task1)
	if err != nil {
		t.Errorf("AddTask() failed: %v", err)
	}

	// Now add task2 should succeed
	err = s.AddTask(task2)
	if err != nil {
		t.Errorf("AddTask() failed: %v", err)
	}
}

func TestScheduler_GetTaskStatus(t *testing.T) {
	s := scheduler.NewScheduler()

	task := &scheduler.Task{
		Name:     "test-task",
		Interval: 5 * time.Minute,
		Handler:  func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error { return nil },
		Enabled:  true,
	}

	err := s.AddTask(task)
	if err != nil {
		t.Fatalf("AddTask() failed: %v", err)
	}

	status := s.GetTaskStatus()
	if status == nil {
		t.Fatal("GetTaskStatus() returned nil")
	}

	if _, exists := status["test-task"]; !exists {
		t.Error("GetTaskStatus() should contain the added task")
	}
}

func TestScheduler_Start_Stop(t *testing.T) {
	s := scheduler.NewScheduler()

	task := &scheduler.Task{
		Name:     "test-task",
		Interval: 1 * time.Second,
		Handler:  func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error { return nil },
		Enabled:  true,
	}

	err := s.AddTask(task)
	if err != nil {
		t.Fatalf("AddTask() failed: %v", err)
	}

	// Start the scheduler
	err = s.Start(nil, nil)
	if err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	// Starting again should fail
	err = s.Start(nil, nil)
	if err == nil {
		t.Error("Start() should fail when already running")
	}

	// Stop the scheduler
	s.Stop()

	// Stopping again should be idempotent
	s.Stop()
}

func TestCreateDefaultTasks(t *testing.T) {
	tasks := scheduler.CreateDefaultTasks()
	if tasks == nil {
		t.Fatal("CreateDefaultTasks() returned nil")
	}

	if len(tasks) == 0 {
		t.Error("CreateDefaultTasks() should return at least one task")
	}

	// Check that all tasks have required fields
	for _, task := range tasks {
		if task.Name == "" {
			t.Error("Task should have a name")
		}
		if task.Handler == nil {
			t.Error("Task should have a handler")
		}
	}
}

func TestScheduler_GetTaskStatus_EmptyScheduler(t *testing.T) {
	s := scheduler.NewScheduler()

	status := s.GetTaskStatus()
	if status == nil {
		t.Fatal("GetTaskStatus() returned nil")
	}

	if len(status) != 0 {
		t.Error("GetTaskStatus() should return empty map for empty scheduler")
	}
}
