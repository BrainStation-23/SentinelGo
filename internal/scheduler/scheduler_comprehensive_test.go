package scheduler_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

func TestScheduler_AddTask_Duplicate(t *testing.T) {
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

	// Adding the same task again should fail
	err = s.AddTask(task)
	if err == nil {
		t.Error("AddTask() should fail when adding duplicate task")
	}
}

func TestScheduler_GetTaskStatus_NonExistent(t *testing.T) {
	s := scheduler.NewScheduler()

	status := s.GetTaskStatus()
	if status == nil {
		t.Error("GetTaskStatus() should not return nil")
	}

	// Check that the non-existent task is not in the status map
	if _, exists := status["non-existent-task"]; exists {
		t.Error("Non-existent task should not be in status map")
	}
}

func TestScheduler_GetTaskStatus_AfterAdd(t *testing.T) {
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

	// Check that the task is in the status map
	status := s.GetTaskStatus()
	if _, exists := status["test-task"]; !exists {
		t.Error("Task should be in status map after AddTask")
	}
}
