package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"sentinelgo/internal/dlp"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
)

const rpcEnqueueEvents = "agent_enqueue_dlp_events"

// MaxRequestBytes is the ingestion limit for one enqueue call
// (docs/agent-ingestion.md: 1 MB).
const MaxRequestBytes = 1 << 20

// SendEvents enqueues one batch through agent_enqueue_dlp_events, with the
// agent-enqueue retry policy: 5xx and network errors back off and retry until
// ctx ends, 401 is returned for DoWithAuthRetry, and any other 4xx returns an
// error wrapping dlp.ErrEventsRejected (the batch is dropped). It implements
// dlp.EventSender.
func (s *Service) SendEvents(ctx context.Context, evs []events.Event) error {
	body, err := json.Marshal(map[string]any{"payload": map[string]any{"events": evs}})
	if err != nil {
		return fmt.Errorf("encode DLP events: %w", err)
	}
	// Postgres rejects NUL in jsonb; a source app name could carry one.
	body = sanitize.StripJSONNUL(body)
	if len(body) > MaxRequestBytes {
		return fmt.Errorf("%w: batch is %d bytes, over the %d-byte limit", dlp.ErrEventsRejected, len(body), MaxRequestBytes)
	}

	notEnqueued := false
	err = rpcutil.WithEnqueueRetry(rpcutil.ReportDroppedPayloads(ctx), func(ctx context.Context) error {
		var raw []byte
		if err := s.client().RPC(ctx, rpcEnqueueEvents, json.RawMessage(body), &raw, s.deviceHeader()); err != nil {
			return err
		}
		var resp rpcutil.EnqueueResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			// Accepted; an unparsable body must not cause a resend.
			log.Printf("[dlp] events accepted but response parse failed: %v", err)
			return nil
		}
		notEnqueued = !resp.Enqueued
		return nil
	})
	if errors.Is(err, rpcutil.ErrPayloadDropped) {
		return fmt.Errorf("%w: %w", dlp.ErrEventsRejected, err)
	}
	if err == nil && notEnqueued {
		// Keep the rows; the next sync retries them.
		return fmt.Errorf("%s: server did not enqueue the batch", rpcEnqueueEvents)
	}
	return err
}
