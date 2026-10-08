package internal

// Shutdown-ordering tests for MainIntegration and the TaskManager goroutine
// (issue #113): Stop must cancel and join the TaskManager's Run goroutine
// before it returns, so nothing touches the task store after it is closed.

import (
	"context"
	"net/http"
	"testing"
	"time"

	tasksvc "sentinelgo/internal/service/task"
)

// startWithTrackedTaskManager starts a MainIntegration with task polling on and
// wraps the TaskManager Run hook so the test can observe when Run is entered
// and when it has returned. The ctx passed to Start is never cancelled by the
// test before Stop: Stop alone must bring the TaskManager down.
func startWithTrackedTaskManager(t *testing.T) (mi *MainIntegration, started, exited chan struct{}) {
	t.Helper()
	stubDefaultTasks(t)
	resetUpdaterRetrier(t)

	started = make(chan struct{})
	exited = make(chan struct{})
	origRun := runTaskManager
	runTaskManager = func(tm *tasksvc.TaskManager, ctx context.Context) error {
		close(started)
		defer close(exited)
		return origRun(tm, ctx)
	}
	t.Cleanup(func() { runTaskManager = origRun })

	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	cfg.EnableTaskPolling = true

	ctx, cancel := context.WithCancel(context.Background())
	// Safety net only (registered after the hook restore, so it runs first):
	// never leak the Run goroutine past the test even if Stop failed to join it.
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Error("TaskManager Run goroutine leaked past test cleanup")
		}
	})

	mi = NewMainIntegration(cfg)
	if err := mi.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if mi.taskManager == nil {
		t.Fatal("task manager was not started")
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("TaskManager Run was not invoked")
	}
	return mi, started, exited
}

// TestStop_JoinsTaskManagerRun is the regression test for #113: once Stop
// returns, the TaskManager Run goroutine must have exited. Previously Stop only
// closed the task store; Run kept going on the caller's (still live) ctx and
// could poll/execute against the closed store.
func TestStop_JoinsTaskManagerRun(t *testing.T) {
	mi, _, exited := startWithTrackedTaskManager(t)

	if err := mi.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	select {
	case <-exited:
	default:
		t.Fatal("Stop returned while the TaskManager Run goroutine was still running (store closed under a live poller)")
	}
}

// TestStop_TwiceAfterJoin checks a second Stop (after the TaskManager has been
// joined and closed) is a harmless no-op for the task manager.
func TestStop_TwiceAfterJoin(t *testing.T) {
	mi, _, _ := startWithTrackedTaskManager(t)
	if err := mi.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if err := mi.Stop(); err != nil {
		t.Fatalf("second Stop() error: %v", err)
	}
}

// TestStop_BoundedWhenTaskManagerIgnoresCancel checks Stop does not hang
// shutdown when the TaskManager goroutine fails to honour cancellation: it
// waits taskManagerStopTimeout, logs a warning and carries on.
func TestStop_BoundedWhenTaskManagerIgnoresCancel(t *testing.T) {
	stubDefaultTasks(t)
	resetUpdaterRetrier(t)

	origTimeout := taskManagerStopTimeout
	taskManagerStopTimeout = 50 * time.Millisecond
	t.Cleanup(func() { taskManagerStopTimeout = origTimeout })

	started := make(chan struct{})
	release := make(chan struct{})
	origRun := runTaskManager
	runTaskManager = func(*tasksvc.TaskManager, context.Context) error {
		close(started)
		<-release // ignores ctx entirely
		return nil
	}
	t.Cleanup(func() { runTaskManager = origRun })
	t.Cleanup(func() { close(release) })

	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	cfg.EnableTaskPolling = true

	lw := watchLog(t)
	mi := NewMainIntegration(cfg)
	if err := mi.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	<-started

	stopped := make(chan error, 1)
	go func() { stopped <- mi.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop() error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung on a TaskManager that ignores cancellation")
	}
	if !lw.contains("TaskManager did not stop within") {
		t.Error("expected a warning that the TaskManager did not stop in time")
	}
}
