package scheduler_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

// TestScheduler_PanicRecovery verifies that a panicking task handler does not
// crash the whole agent — the scheduler must recover and keep running.
func TestScheduler_PanicRecovery(t *testing.T) {
	s := scheduler.NewScheduler()

	task := &scheduler.Task{
		Name:    "panicking-task",
		Enabled: true,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			panic("deliberate test panic")
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	// Start runs initial tasks in a goroutine. The panic should be recovered.
	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the initial task goroutine time to run and recover from the panic.
	time.Sleep(200 * time.Millisecond)

	// If we reach here without crashing, panic recovery works.
	// Stop should also complete cleanly.
	s.Stop()
}

// TestScheduler_InitialTaskRuns verifies that a task runs on scheduler start
// even when no periodic interval is set.
func TestScheduler_InitialTaskRuns(t *testing.T) {
	var count atomic.Int64

	s := scheduler.NewScheduler()
	task := &scheduler.Task{
		Name:    "initial-task",
		Enabled: true,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			count.Add(1)
			return nil
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Initial tasks run in a background goroutine; wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if count.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.Stop()

	if count.Load() == 0 {
		t.Error("expected initial task to run at least once, but count is 0")
	}
}

// TestScheduler_DisabledTaskSkipped verifies that a task with Enabled=false is
// not executed by the initial-task pass.
func TestScheduler_DisabledTaskSkipped(t *testing.T) {
	var count atomic.Int64

	s := scheduler.NewScheduler()
	task := &scheduler.Task{
		Name:    "disabled-task",
		Enabled: false,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			count.Add(1)
			return nil
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	s.Stop()

	if count.Load() != 0 {
		t.Errorf("disabled task ran %d time(s); expected 0", count.Load())
	}
}

// TestScheduler_PeriodicExecution verifies that a periodic task is executed
// after its ticker fires. Because the scheduler's heartbeat is 1 second, this
// test sleeps just over that.
func TestScheduler_PeriodicExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping periodic execution test in -short mode (requires >1s sleep)")
	}

	var count atomic.Int64

	s := scheduler.NewScheduler()
	task := &scheduler.Task{
		Name:     "periodic-task",
		Interval: 100 * time.Millisecond,
		Enabled:  true,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			count.Add(1)
			return nil
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for at least one heartbeat cycle (1s) plus a buffer, so the periodic
	// ticker has had a chance to fire and be detected by the heartbeat.
	time.Sleep(1500 * time.Millisecond)
	s.Stop()

	// The task should have run at least once (initial run) and at least once
	// via periodic (heartbeat detected the ticker).
	if count.Load() < 2 {
		t.Errorf("expected >=2 runs (initial + periodic), got %d", count.Load())
	}
}

// TestScheduler_TaskErrorDoesNotCrash verifies that a handler returning an error
// does not stop the scheduler.
func TestScheduler_TaskErrorDoesNotCrash(t *testing.T) {
	var count atomic.Int64

	s := scheduler.NewScheduler()
	task := &scheduler.Task{
		Name:    "erroring-task",
		Enabled: true,
		Handler: func(ctx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			count.Add(1)
			return context.DeadlineExceeded // non-nil error
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	s.Stop() // must not block or panic

	if count.Load() == 0 {
		t.Error("expected erroring task to run, but count is 0")
	}
}

// TestScheduler_DuplicateTaskRejected verifies that AddTask returns an error when
// a task with the same name is added twice.
func TestScheduler_DuplicateTaskRejected(t *testing.T) {
	s := scheduler.NewScheduler()

	task := &scheduler.Task{
		Name:    "unique-task",
		Enabled: true,
		Handler: func(_ context.Context, _ *config.Config, _ *authsvc.Service) error { return nil },
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("first AddTask: %v", err)
	}

	dup := &scheduler.Task{
		Name:    "unique-task", // same name
		Enabled: true,
		Handler: func(_ context.Context, _ *config.Config, _ *authsvc.Service) error { return nil },
	}

	if err := s.AddTask(dup); err == nil {
		t.Error("expected error when adding duplicate task name, got nil")
	}
}

// TestScheduler_PanicRecovery_SubsequentTaskRuns verifies that after a panicking
// initial task, a second non-panicking task still runs and increments its counter.
func TestScheduler_PanicRecovery_SubsequentTaskRuns(t *testing.T) {
	var safeCount atomic.Int64

	s := scheduler.NewScheduler()

	// This task will panic on its initial run.
	panicker := &scheduler.Task{
		Name:    "panic-task",
		Enabled: true,
		Handler: func(_ context.Context, _ *config.Config, _ *authsvc.Service) error {
			panic("deliberate panic in test")
		},
	}
	// This task should still run despite the sibling panic.
	safe := &scheduler.Task{
		Name:    "safe-task",
		Enabled: true,
		Handler: func(_ context.Context, _ *config.Config, _ *authsvc.Service) error {
			safeCount.Add(1)
			return nil
		},
	}

	if err := s.AddTask(panicker); err != nil {
		t.Fatalf("AddTask panicker: %v", err)
	}
	if err := s.AddTask(safe); err != nil {
		t.Fatalf("AddTask safe: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for the initial task goroutine to complete both tasks.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if safeCount.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.Stop()

	if safeCount.Load() == 0 {
		t.Error("safe task did not run after sibling panic; panic recovery may have broken task loop")
	}
}

// TestScheduler_StopUnblocksBlockingTask verifies that Stop cancels the internal
// context, which unblocks a task that is waiting on it, and Stop returns cleanly.
func TestScheduler_StopUnblocksBlockingTask(t *testing.T) {
	s := scheduler.NewScheduler()
	task := &scheduler.Task{
		Name:    "blocking-task",
		Enabled: true,
		Handler: func(taskCtx context.Context, cfg *config.Config, authSvc *authsvc.Service) error {
			<-taskCtx.Done()
			return taskCtx.Err()
		},
	}

	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.Start(nil, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK — Stop returned cleanly
	case <-time.After(5 * time.Second):
		t.Error("Stop() did not return within 5s")
	}
}
