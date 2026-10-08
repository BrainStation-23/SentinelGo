// Package rpcutil holds the agent-enqueue RPC helpers shared by every
// reporting path: the PostEnqueue call and its retry policy.
package rpcutil

import (
	"context"
	"encoding/json"
	"log"

	"sentinelgo/internal/supabase"
)

// PostEnqueue calls the agent_enqueue_* RPC fn through c with params as the
// JSON body, applying the agent-enqueue retry policy (see WithEnqueueRetry).
// logTag identifies the caller in log lines, e.g. "software", "services",
// "inventory". A success response that cannot be parsed is only logged: the
// payload was accepted, so it must not be resent.
func PostEnqueue(ctx context.Context, c *supabase.Client, fn string, params any, logTag string, opts ...supabase.CallOption) error {
	return WithEnqueueRetry(ctx, func(ctx context.Context) error {
		var raw []byte
		if err := c.RPC(ctx, fn, params, &raw, opts...); err != nil {
			return err
		}
		var enqResp EnqueueResponse
		if err := json.Unmarshal(raw, &enqResp); err != nil {
			log.Printf("[%s] enqueue accepted but response parse failed: %v", logTag, err)
		} else {
			log.Printf("[%s] enqueued: msg_id=%d queue=%s", logTag, enqResp.MsgID, enqResp.Queue)
		}
		return nil
	})
}
