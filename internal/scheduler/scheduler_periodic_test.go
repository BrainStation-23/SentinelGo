package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	authsvc "sentinelgo/internal/service/auth"
)

// These are fast, direct unit tests for maybeDispatchTask and
// executePeriodicTask now that the complexity refactor split them out of
// runPeriodicTasks. Previously this logic was only reachable via
// TestScheduler_PeriodicExecution, which needs a real >1s sleep and is
// skipped under -short (the mode CI's coverage run actually uses) - these
// tests give it real, fast, always-on coverage instead.

func countingHandler(count *atomic.Int64) TaskHandler {
	return func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
		count.Add(1)
		return nil
	}
}

func readyTicker(t *testing.T) *time.Ticker {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	t.Cleanup(ticker.Stop)
	time.Sleep(3 * time.Millisecond) // let it fire at least once
	return ticker
}

func TestMaybeDispatchTask_FiresWhenReady(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "quick-task", Enabled: true, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", readyTicker(t), nil)
	s.wg.Wait()

	if count.Load() != 1 {
		t.Errorf("handler ran %d time(s), want 1", count.Load())
	}
}

func TestMaybeDispatchTask_TickerNotReady(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "quick-task", Enabled: true, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	// A ticker with a long interval won't have fired yet.
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", ticker, nil)
	s.wg.Wait()

	if count.Load() != 0 {
		t.Errorf("handler ran %d time(s), want 0 (ticker hasn't fired)", count.Load())
	}
}

func TestMaybeDispatchTask_JitterNotElapsed(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "quick-task", Enabled: true, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	startAfter := map[string]time.Time{"quick-task": time.Now().Add(time.Hour)}
	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", readyTicker(t), startAfter)
	s.wg.Wait()

	if count.Load() != 0 {
		t.Errorf("handler ran %d time(s), want 0 (jitter not elapsed)", count.Load())
	}
}

func TestMaybeDispatchTask_DisabledTaskSkipped(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "quick-task", Enabled: false, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", readyTicker(t), nil)
	s.wg.Wait()

	if count.Load() != 0 {
		t.Errorf("handler ran %d time(s), want 0 (task disabled)", count.Load())
	}
}

func TestMaybeDispatchTask_DependencyNotMetSkipped(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	dep := &Task{Name: "dep-task", Enabled: true, Handler: countingHandler(&atomic.Int64{})}
	if err := s.AddTask(dep); err != nil {
		t.Fatalf("AddTask(dep): %v", err)
	}
	task := &Task{Name: "quick-task", Enabled: true, Dependencies: []string{"dep-task"}, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	// dep-task has never run (LastRun is zero), so the dependency isn't met.
	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", readyTicker(t), nil)
	s.wg.Wait()

	if count.Load() != 0 {
		t.Errorf("handler ran %d time(s), want 0 (dependency not met)", count.Load())
	}
}

func TestMaybeDispatchTask_AlreadyRunningSkipsConcurrentTick(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "quick-task", Enabled: true, Handler: countingHandler(&count)}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}
	task.Running.Store(true) // simulate a handler already in flight

	s.maybeDispatchTask(context.Background(), nil, nil, "quick-task", readyTicker(t), nil)
	s.wg.Wait()

	if count.Load() != 0 {
		t.Errorf("handler ran %d time(s), want 0 (already running)", count.Load())
	}
}

func TestExecutePeriodicTask_Directly(t *testing.T) {
	var count atomic.Int64
	s := NewScheduler()
	task := &Task{Name: "direct-task", Enabled: true, Handler: countingHandler(&count)}

	s.wg.Add(1)
	s.executePeriodicTask(context.Background(), nil, nil, task, "direct-task")

	if count.Load() != 1 {
		t.Errorf("handler ran %d time(s), want 1", count.Load())
	}
	if task.LastRun.IsZero() {
		t.Error("LastRun should be set after execution")
	}
	if task.Running.Load() {
		t.Error("Running should be false after execution completes")
	}
}

func TestExecutePeriodicTask_HandlerError(t *testing.T) {
	s := NewScheduler()
	sentinel := context.DeadlineExceeded
	task := &Task{
		Name:    "erroring-task",
		Enabled: true,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			return sentinel
		},
	}

	s.wg.Add(1)
	s.executePeriodicTask(context.Background(), nil, nil, task, "erroring-task")

	if task.consecutiveFailures.Load() != 1 {
		t.Errorf("consecutiveFailures = %d, want 1", task.consecutiveFailures.Load())
	}
}
