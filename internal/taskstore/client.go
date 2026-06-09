package taskstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/httpx"
)

// Client handles RPC calls to agent_get_tasks and agent_update_task
type Client struct {
	supabaseURL string
	anonKey     string // Supabase anon/public API key for apikey header
	accessToken string // User JWT access token for Authorization bearer
	client      *http.Client
}

// NewClient creates a new RPC client. anonKey is sent as the apikey header,
// accessToken is sent as the Authorization bearer on every request.
func NewClient(supabaseURL, anonKey, accessToken string) *Client {
	return &Client{
		supabaseURL: supabaseURL,
		anonKey:     anonKey,
		accessToken: accessToken,
		client:      httpx.NewClient(30 * time.Second),
	}
}

// UpdateToken updates the access token (e.g., after refresh)
func (c *Client) UpdateToken(token string) {
	c.accessToken = token
}

// GetTasks calls agent_get_tasks RPC and returns the response
func (c *Client) GetTasks(ctx context.Context) (*AgentTasksResponse, error) {
	url := fmt.Sprintf("%s/rest/v1/rpc/agent_get_tasks", c.supabaseURL)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Client: Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: status 401")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result AgentTasksResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateTask calls agent_update_task RPC
func (c *Client) UpdateTask(ctx context.Context, taskID, status, note string) error {
	url := fmt.Sprintf("%s/rest/v1/rpc/agent_update_task", c.supabaseURL)

	payload := map[string]string{
		"p_task_id": taskID,
		"p_status":  status,
	}
	if note != "" {
		payload["p_note"] = note
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Client: Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update task failed: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.anonKey)
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
}
