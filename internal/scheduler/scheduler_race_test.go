package scheduler_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

// TestScheduler_StatusReadDuringRuns reads GetTaskStatus continuously while the
// initial run and periodic ticks (including dependency checks against a task
// that is itself re-running) write LastRun. Under -race this caught the
// unsynchronised Task.LastRun write (issue #114). Without -race it still asserts
// that LastRun becomes visible through GetTaskStatus and that the dependent
// task's dependency check passes.
func TestScheduler_StatusReadDuringRuns(t *testing.T) {
	var depRuns, childRuns atomic.Int32
	s := scheduler.NewScheduler()
	dep := &scheduler.Task{
		Name:     "dep",
		Interval: time.Second,
		Enabled:  true,
		Handler: func(context.Context, *config.Config, *authsvc.Service) error {
			depRuns.Add(1)
			return nil
		},
	}
	child := &scheduler.Task{
		Name:         "child",
		Interval:     time.Second,
		Dependencies: []string{"dep"},
		Enabled:      true,
		Handler: func(context.Context, *config.Config, *authsvc.Service) error {
			childRuns.Add(1)
			return nil
		},
	}
	for _, task := range []*scheduler.Task{dep, child} {
		if err := s.AddTask(task); err != nil {
			t.Fatalf("AddTask(%s): %v", task.Name, err)
		}
	}

	before := time.Now()
	stopReaders := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				for _, st := range s.GetTaskStatus() {
					_ = st.LastRun.IsZero()
				}
			}
		}()
	}

	if err := s.Start(loadTestConfig(t), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for both tasks to have run at least twice: once from the initial run
	// and once from a periodic tick, which goes through checkDependencies.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (depRuns.Load() < 2 || childRuns.Load() < 2) {
		time.Sleep(20 * time.Millisecond)
	}

	s.Stop()
	close(stopReaders)
	readers.Wait()

	if depRuns.Load() < 2 || childRuns.Load() < 2 {
		t.Fatalf("runs: dep=%d child=%d, want >= 2 each (periodic child run needs dependency check to pass)",
			depRuns.Load(), childRuns.Load())
	}
	status := s.GetTaskStatus()
	for _, name := range []string{"dep", "child"} {
		st, ok := status[name]
		if !ok {
			t.Fatalf("status missing %q", name)
		}
		if st.LastRun.Before(before) {
			t.Errorf("%s LastRun = %v, want >= %v", name, st.LastRun, before)
		}
	}
}

// TestScheduler_AddTaskAfterStartRejected verifies that AddTask refuses to
// mutate the task set once the scheduler has started. The running goroutines
// read the task map and order without the lock, so a post-Start AddTask was a
// data race (issue #114); it is now rejected with an error and the task is not
// registered.
func TestScheduler_AddTaskAfterStartRejected(t *testing.T) {
	s := scheduler.NewScheduler()
	noop := func(context.Context, *config.Config, *authsvc.Service) error { return nil }
	if err := s.AddTask(&scheduler.Task{Name: "first", Interval: time.Second, Enabled: true, Handler: noop}); err != nil {
		t.Fatalf("AddTask before Start: %v", err)
	}
	if err := s.Start(loadTestConfig(t), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	err := s.AddTask(&scheduler.Task{Name: "late", Interval: time.Second, Enabled: true, Handler: noop})
	if err == nil {
		t.Fatal("AddTask after Start returned nil; want error")
	}
	if _, ok := s.GetTaskStatus()["late"]; ok {
		t.Error("task added after Start was registered; want it rejected")
	}

	// Still rejected after Stop: the scheduler may be restarted with the same
	// task set, so it stays frozen once started.
	s.Stop()
	if err := s.AddTask(&scheduler.Task{Name: "late2", Interval: time.Second, Enabled: true, Handler: noop}); err == nil {
		t.Error("AddTask after Stop returned nil; want error")
	}
}
