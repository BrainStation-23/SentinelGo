package task

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// pendingClient is a TaskClient that can also answer the pending-task check.
type pendingClient struct {
	pending  bool
	err      error
	checks   int
	getCalls int
}

func (c *pendingClient) GetTasks(context.Context) (*taskstore.AgentTasksResponse, error) {
	c.getCalls++
	return &taskstore.AgentTasksResponse{}, nil
}

func (c *pendingClient) UpdateTask(context.Context, string, string, string) error { return nil }

func (c *pendingClient) HasPendingTasks(context.Context) (bool, error) {
	c.checks++
	return c.pending, c.err
}

// plainClient can't answer the pending-task check (older test doubles).
type plainClient struct{}

func (plainClient) GetTasks(context.Context) (*taskstore.AgentTasksResponse, error) {
	return &taskstore.AgentTasksResponse{}, nil
}

func (plainClient) UpdateTask(context.Context, string, string, string) error { return nil }

func newPendingManager(t *testing.T, client TaskClient) *TaskManager {
	t.Helper()
	cfg := &config.Config{TaskDBPath: filepath.Join(t.TempDir(), "tasks.sqlite")}
	svc, err := NewTaskPollingServiceWithClient(cfg, cfg.TaskDBPath, client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	tm := NewTaskManagerWithPollingService(cfg, svc)
	t.Cleanup(func() { _ = tm.Close() })
	return tm
}

func TestTasksPending(t *testing.T) {
	c := &pendingClient{pending: true}
	tm := newPendingManager(t, c)
	if !tm.tasksPending(context.Background(), time.Now()) {
		t.Error("queued task not reported")
	}
	c.pending = false
	if tm.tasksPending(context.Background(), time.Now()) {
		t.Error("nothing queued, reported pending")
	}
}

func TestTasksPending_OlderServerBacksOff(t *testing.T) {
	c := &pendingClient{err: taskstore.ErrNoPendingCheck}
	tm := newPendingManager(t, c)
	now := time.Now()
	if tm.tasksPending(context.Background(), now) {
		t.Fatal("reported pending without the check")
	}
	// Off for pendingCheckRetry: no further requests until then.
	tm.tasksPending(context.Background(), now.Add(pendingCheckRetry-time.Minute))
	if c.checks != 1 {
		t.Errorf("checked %d times while backed off", c.checks)
	}
	// Then it tries again, so a server upgrade is picked up.
	c.err, c.pending = nil, true
	if !tm.tasksPending(context.Background(), now.Add(pendingCheckRetry+time.Second)) || c.checks != 2 {
		t.Errorf("no retry after the back-off (checks=%d)", c.checks)
	}
}

func TestTasksPending_OtherErrorsRetryNextTime(t *testing.T) {
	c := &pendingClient{err: errors.New("network down")}
	tm := newPendingManager(t, c)
	tm.tasksPending(context.Background(), time.Now())
	tm.tasksPending(context.Background(), time.Now())
	if c.checks != 2 {
		t.Errorf("checks = %d, want 2 (no back-off for transient errors)", c.checks)
	}
}

func TestTasksPending_ClientWithoutCheck(t *testing.T) {
	tm := newPendingManager(t, plainClient{})
	if tm.tasksPending(context.Background(), time.Now()) {
		t.Error("reported pending without a check")
	}
	if tm.pendingCheckOffUntil.IsZero() {
		t.Error("check not turned off for a client that can't do it")
	}
}

func TestTaskCheckInterval(t *testing.T) {
	if got := (&config.Config{}).GetTaskCheckInterval(); got != time.Minute {
		t.Errorf("default = %v, want 1m", got)
	}
	if got := (&config.Config{TaskCheckInterval: config.Duration(30 * time.Second)}).GetTaskCheckInterval(); got != 30*time.Second {
		t.Errorf("set = %v, want 30s", got)
	}
}
