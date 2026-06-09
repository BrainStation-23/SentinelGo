package task_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task"
	"sentinelgo/internal/taskstore"
)

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		SupabaseURL:           "https://placeholder.supabase.co",
		AccessToken:           "test-access-token",
		AgentID:               "test-agent-id",
		RefreshToken:          "test-refresh-token",
		EnableTaskPolling:     true,
		TaskPollingInterval:   config.Duration(5 * time.Minute),
		TaskExecutionInterval: config.Duration(30 * time.Second),
	}
}

// mockTaskClient is a no-op TaskClient for tests.
type mockTaskClient struct {
	tasks     []taskstore.Task
	getErr    error
	updateErr error
}

func (m *mockTaskClient) GetTasks(_ context.Context) (*taskstore.AgentTasksResponse, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return &taskstore.AgentTasksResponse{Tasks: m.tasks}, nil
}

func (m *mockTaskClient) UpdateTask(_ context.Context, _, _, _ string) error {
	return m.updateErr
}

func (m *mockTaskClient) UpdateToken(_ string) {}

// mockTokenRefresher is a no-op TokenRefresher for tests.
type mockTokenRefresher struct {
	token  string
	err    error
	called bool
}

func (m *mockTokenRefresher) RefreshToken(_ context.Context) (string, error) {
	m.called = true
	return m.token, m.err
}

// compile-time check that mockTaskClient satisfies task.TaskClient.
var _ task.TaskClient = (*mockTaskClient)(nil)

// compile-time check that mockTokenRefresher satisfies task.TokenRefresher.
var _ task.TokenRefresher = (*mockTokenRefresher)(nil)
