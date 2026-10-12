package taskstore

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"sentinelgo/internal/supabase"
)

// Client handles RPC calls to agent_get_tasks and agent_update_task.
type Client struct {
	sb *supabase.Client
	// noResultParam is set once the server shows it has no p_result
	// parameter (an older backend), so later updates skip it instead of
	// paying for a failed call each time.
	noResultParam atomic.Bool
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
	return c.UpdateTaskWithResult(ctx, taskID, status, note, nil)
}

// UpdateTaskWithResult calls agent_update_task with an optional structured
// result (p_result, sentinel-ops#49). A backend without that parameter
// answers PGRST202 ("function not found"); the update is then retried once
// without it, and p_result is not sent again for the life of the process.
func (c *Client) UpdateTaskWithResult(ctx context.Context, taskID, status, note string, result map[string]interface{}) error {
	params := map[string]interface{}{
		"p_task_id": taskID,
		"p_status":  status,
	}
	if note != "" {
		params["p_note"] = note
	}
	withResult := result != nil && !c.noResultParam.Load()
	if withResult {
		params["p_result"] = result
	}

	err := c.sb.RPC(ctx, "agent_update_task", params, nil)
	if withResult && isFunctionNotFound(err) {
		c.noResultParam.Store(true)
		log.Printf("TaskStore: server has no agent_update_task p_result parameter; sending task results without it")
		delete(params, "p_result")
		err = c.sb.RPC(ctx, "agent_update_task", params, nil)
	}
	if err != nil {
		return fmt.Errorf("update task failed: %w", err)
	}
	return nil
}

// isFunctionNotFound reports a PostgREST PGRST202: no function matches the
// name and named arguments sent.
func isFunctionNotFound(err error) bool {
	e, ok := supabase.AsAPIError(err)
	return ok && supabase.IsNotFound(err) && e.Code == "PGRST202"
}
