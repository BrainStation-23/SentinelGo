package task_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"sentinelgo/internal/service/task"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/taskstore"
)

// scriptedTaskClient returns updateErrs in order from UpdateTask, then nil.
type scriptedTaskClient struct {
	mu          sync.Mutex
	updateErrs  []error
	updateCalls int
}

func (c *scriptedTaskClient) GetTasks(_ context.Context) (*taskstore.AgentTasksResponse, error) {
	return &taskstore.AgentTasksResponse{}, nil
}

func (c *scriptedTaskClient) UpdateTask(_ context.Context, _, _, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateCalls++
	if len(c.updateErrs) == 0 {
		return nil
	}
	err := c.updateErrs[0]
	c.updateErrs = c.updateErrs[1:]
	return err
}

func (c *scriptedTaskClient) UpdateToken(_ string) {}

func expiredJWT() error {
	return &supabase.APIError{Status: 401, Code: "PGRST301", Message: "JWT expired", Method: "POST", Path: "/rest/v1/rpc/agent_update_task"}
}

// UpdateTask used to have no 401 handling, so an expired token silently left
// results unsynced until the next poll happened to refresh it.
func TestReportTaskStatus_401_RecoversAndRetriesOnce(t *testing.T) {
	client := &scriptedTaskClient{updateErrs: []error{expiredJWT()}}
	refresher := &mockTokenRefresher{token: "new-token"}
	svc, err := task.NewTaskPollingServiceWithClient(loadTestConfig(t), filepath.Join(t.TempDir(), "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	_ = svc.ReportTaskStatus(context.Background(), "task-1", "success", "")

	if !refresher.called {
		t.Error("a 401 from UpdateTask must trigger session recovery")
	}
	if client.updateCalls != 2 {
		t.Errorf("UpdateTask calls = %d, want 2 (401 + one retry)", client.updateCalls)
	}
}

func TestReportTaskStatus_403_NoRecovery(t *testing.T) {
	forbidden := &supabase.APIError{Status: 403, Code: "42501", Method: "POST", Path: "/rest/v1/rpc/agent_update_task"}
	client := &scriptedTaskClient{updateErrs: []error{forbidden}}
	refresher := &mockTokenRefresher{token: "new-token"}
	svc, err := task.NewTaskPollingServiceWithClient(loadTestConfig(t), filepath.Join(t.TempDir(), "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	_ = svc.ReportTaskStatus(context.Background(), "task-1", "success", "")

	if refresher.called {
		t.Error("a 403 must not trigger session recovery")
	}
	if client.updateCalls != 1 {
		t.Errorf("UpdateTask calls = %d, want 1", client.updateCalls)
	}
}

func TestReportTaskStatus_RecoveryFails_NoRetry(t *testing.T) {
	client := &scriptedTaskClient{updateErrs: []error{expiredJWT()}}
	refresher := &mockTokenRefresher{err: errors.New("breaker open")}
	svc, err := task.NewTaskPollingServiceWithClient(loadTestConfig(t), filepath.Join(t.TempDir(), "tasks.db"), client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	defer func() { _ = svc.Close() }()
	svc.SetTokenRefresher(refresher)

	_ = svc.ReportTaskStatus(context.Background(), "task-1", "success", "")

	if client.updateCalls != 1 {
		t.Errorf("UpdateTask calls = %d, want 1 (no retry when recovery fails)", client.updateCalls)
	}
}
