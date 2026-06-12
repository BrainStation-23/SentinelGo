package task

// White-box tests for unexported executor functions.
// Package task (not task_test) is required to access resolveTaskTimeout and cancelOverdueTasks.

import (
	"context"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/taskstore"
)

func TestResolveTaskTimeout_Default(t *testing.T) {
	task := taskstore.Task{Payload: map[string]interface{}{}}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout with no payload: got %v, want %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_FromPayload(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(60)},
	}
	got := resolveTaskTimeout(task)
	if got != 60*time.Minute {
		t.Errorf("resolveTaskTimeout(60 min): got %v, want %v", got, 60*time.Minute)
	}
}

func TestResolveTaskTimeout_CappedAtMax(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(9999)},
	}
	got := resolveTaskTimeout(task)
	if got != maxTaskTimeout {
		t.Errorf("resolveTaskTimeout(9999 min): got %v, want %v (maxTaskTimeout)", got, maxTaskTimeout)
	}
}

func TestResolveTaskTimeout_ZeroUsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(0)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(0): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_NegativeUsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(-5)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(-5): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_FractionalMinutes(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(0.5)},
	}
	got := resolveTaskTimeout(task)
	if got != 30*time.Second {
		t.Errorf("resolveTaskTimeout(0.5 min): got %v, want 30s", got)
	}
}

func TestResolveTaskTimeout_WrongType_UsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": "not-a-number"},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(string value): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_MissingKey_UsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"something_else": float64(10)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(missing key): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestCancelOverdueTasks_CancelsStuckTask(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}

	cancelled := make(chan struct{}, 1)
	ctx, cancelFn := context.WithCancel(context.Background())
	_ = ctx

	// Wrap the real cancel to detect it was called.
	wrappedCancel := func() {
		cancelled <- struct{}{}
		cancelFn()
	}

	// Set deadline in the past (past deadline + grace).
	pastDeadline := time.Now().Add(-(watchdogGrace + time.Second))
	s.activeRunning["stuck-task"] = activeTask{cancel: wrappedCancel, deadline: pastDeadline}

	s.cancelOverdueTasks()

	select {
	case <-cancelled:
		// correct: stuck task was cancelled
	default:
		t.Error("cancelOverdueTasks should have cancelled the stuck task")
	}
}

func TestCancelOverdueTasks_DoesNotCancelActiveTask(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}

	cancelled := false
	// Set deadline in the future.
	futureDeadline := time.Now().Add(10 * time.Minute)
	s.activeRunning["active-task"] = activeTask{
		cancel:   func() { cancelled = true },
		deadline: futureDeadline,
	}

	s.cancelOverdueTasks()

	if cancelled {
		t.Error("cancelOverdueTasks must not cancel a task that is within its deadline + grace period")
	}
}

func TestCancelOverdueTasks_EmptyMap(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}
	// Should not panic on empty map.
	s.cancelOverdueTasks()
}

func TestRegisterAndDeregisterRunning(t *testing.T) {
	s := &TaskExecutorService{
		activeMu:      sync.Mutex{},
		activeRunning: make(map[string]activeTask),
	}

	deadline := time.Now().Add(5 * time.Minute)
	s.registerRunning("task-1", func() {}, deadline)

	s.activeMu.Lock()
	if _, ok := s.activeRunning["task-1"]; !ok {
		t.Error("registerRunning should add task to activeRunning")
	}
	s.activeMu.Unlock()

	s.deregisterRunning("task-1")

	s.activeMu.Lock()
	if _, ok := s.activeRunning["task-1"]; ok {
		t.Error("deregisterRunning should remove task from activeRunning")
	}
	s.activeMu.Unlock()
}

func TestRegisterRunning_ConcurrentSafety(t *testing.T) {
	s := &TaskExecutorService{
		activeMu:      sync.Mutex{},
		activeRunning: make(map[string]activeTask),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := string(rune('a' + id))
			s.registerRunning(key, func() {}, time.Now().Add(time.Minute))
			s.deregisterRunning(key)
		}(i)
	}
	wg.Wait()
}
