package rpcutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// PostEnqueue POSTs body as JSON to url, authenticated with a Supabase bearer
// token and anon key, applying the agent-enqueue retry policy (see
// WithEnqueueRetry). logTag identifies the caller in log lines, e.g.
// "software", "services", "inventory".
func PostEnqueue(ctx context.Context, client *http.Client, url, accessToken, anonKey string, body []byte, logTag string) error {
	return WithEnqueueRetry(ctx, func(ctx context.Context) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("apikey", anonKey)

		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		var enqResp EnqueueResponse
		if err := json.Unmarshal(respBody, &enqResp); err != nil {
			log.Printf("[%s] enqueue accepted but response parse failed: %v", logTag, err)
		} else {
			log.Printf("[%s] enqueued: msg_id=%d queue=%s", logTag, enqResp.MsgID, enqResp.Queue)
		}
		return resp.StatusCode, nil
	})
}
