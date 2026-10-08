package taskstore

import (
	"context"
	"fmt"
	"sync"

	"sentinelgo/internal/supabase"
)

// Client handles RPC calls to agent_get_tasks and agent_update_task.
type Client struct {
	sb *supabase.Client

	// tokenSource, when set, supplies the access token on every request (the
	// production path: it reads the live config, so a refreshed token is used
	// immediately). Otherwise the static accessToken is used.
	tokenSource func() string

	mu          sync.Mutex
	accessToken string
}

// NewClient creates a client that authenticates with a fixed accessToken
// (replaceable via UpdateToken). anonKey is sent as the apikey header.
func NewClient(supabaseURL, anonKey, accessToken string) *Client {
	c := &Client{accessToken: accessToken}
	c.sb = supabase.New(supabaseURL, anonKey, c.token)
	return c
}

// NewClientWithTokenSource creates a client that reads the access token from
// token on every request, e.g. cfg.GetAccessToken, so it never sends a stale
// token after a refresh.
func NewClientWithTokenSource(supabaseURL, anonKey string, token func() string) *Client {
	c := &Client{tokenSource: token}
	c.sb = supabase.New(supabaseURL, anonKey, c.token)
	return c
}

func (c *Client) token() string {
	if c.tokenSource != nil {
		return c.tokenSource()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken
}

// UpdateToken replaces the static access token. It is a no-op for a client
// built with NewClientWithTokenSource, which always reads the current token.
// Kept so task.TaskClient stays unchanged; removed in Supabase P5.
func (c *Client) UpdateToken(token string) {
	if c.tokenSource != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = token
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
