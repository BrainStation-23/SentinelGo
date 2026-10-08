package taskstore

import (
	"context"
	"fmt"

	"sentinelgo/internal/supabase"
)

// Client handles RPC calls to agent_get_tasks and agent_update_task.
type Client struct {
	sb *supabase.Client
}

// NewClient creates a client that authenticates with a fixed accessToken.
// anonKey is sent as the apikey header. Production code uses
// NewClientWithTokenSource so a refreshed token is picked up immediately.
func NewClient(supabaseURL, anonKey, accessToken string) *Client {
	return NewClientWithTokenSource(supabaseURL, anonKey, func() string { return accessToken })
}

// NewClientWithTokenSource creates a client that reads the access token from
// token on every request, e.g. cfg.GetAccessToken, so it never sends a stale
// token after a refresh.
func NewClientWithTokenSource(supabaseURL, anonKey string, token func() string) *Client {
	return &Client{sb: supabase.New(supabaseURL, anonKey, token)}
}

// GetTasks calls the agent_get_tasks RPC and returns the response.
func (c *Client) GetTasks(ctx context.Context) (*AgentTasksResponse, error) {
	var result AgentTasksResponse
	if err := c.sb.RPC(ctx, "agent_get_tasks", nil, &result); err != nil {
		if supabase.IsUnauthorized(err) {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		return nil, err
	}
	return &result, nil
}

// UpdateTask calls the agent_update_task RPC.
func (c *Client) UpdateTask(ctx context.Context, taskID, status, note string) error {
	payload := map[string]string{
		"p_task_id": taskID,
		"p_status":  status,
	}
	if note != "" {
		payload["p_note"] = note
	}
	if err := c.sb.RPC(ctx, "agent_update_task", payload, nil); err != nil {
		return fmt.Errorf("update task failed: %w", err)
	}
	return nil
}
