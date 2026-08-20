package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/store"
)

const (
	// rpcEnqueueTelemetry is the backend RPC this layer targets. It does not
	// exist yet; the agent stays disabled by default until it does.
	rpcEnqueueTelemetry = "/rest/v1/rpc/agent_enqueue_telemetry"

	// rpcTimeout bounds one drain pass, matching the other enqueue paths.
	rpcTimeout = 60 * time.Second

	// drainBatchSize is how many queued messages are fetched per iteration.
	drainBatchSize = 25

	// maxDrainIterations bounds one Flush so a large backlog cannot monopolise
	// the scheduler tick. Whatever remains is picked up next cycle.
	maxDrainIterations = 40

	// maxDeliveryAttempts is how many times a single message is offered before
	// it is moved to the dead-letter state.
	//
	// It is NOT deleted at that point: a message the backend keeps rejecting is
	// a defect to investigate, and deleting it would be exactly the silent data
	// loss this sender exists to prevent. Dead-lettering retains it for
	// inspection while removing it from the delivery path, so it cannot starve
	// the messages queued behind it. The bounded queue is the eventual backstop,
	// and both eviction and dead-lettering are counted in telemetry health.
	maxDeliveryAttempts = 5
)

// deliveryOutcome classifies what happened to one message.
type deliveryOutcome int

const (
	// outcomeDelivered: the backend acknowledged with a 2xx.
	outcomeDelivered deliveryOutcome = iota
	// outcomeRejected: a non-auth 4xx. The backend refused the payload and
	// retrying the same bytes will not help.
	outcomeRejected
	// outcomeTransient: 5xx or network failure that survived the retry policy.
	outcomeTransient
	// outcomeAuth: 401, to be handled by the caller's session recovery.
	outcomeAuth
)

// FlushResult summarises one drain pass.
type FlushResult struct {
	Delivered int
	Rejected  int
	// DeadLettered counts messages moved out of the delivery path during this
	// flush because they exhausted their attempts.
	DeadLettered int
	// Poisoned counts already-dead-lettered messages encountered. With the
	// dead-letter state in place this should stay at zero; a non-zero value
	// means such a message still reached the delivery path.
	Poisoned int
	// Remaining is the deliverable backlog left after this pass.
	Remaining int
	// DeadLetterDepth is the total number of retained undeliverable messages.
	DeadLetterDepth int
	Sections        []string
}

// Flush drains the outbound telemetry queue.
//
// Ordering guarantees, in the order the requirements demand them:
//   - a queue row is deleted ONLY after the backend acknowledges with a 2xx;
//   - section reconcile timestamps advance ONLY after that same acknowledgement
//     and after the row has actually been removed;
//   - nothing is ever dropped silently — a rejected payload is logged, recorded
//     in the emergency log, counted, and left in the queue.
//
// A 401 stops the drain and is returned so the caller's DoWithAuthRetry can
// recover the session and retry; the rows stay queued meanwhile.
func (s *Service) Flush(ctx context.Context) (FlushResult, error) {
	var result FlushResult

	if s.cfg == nil || s.cfg.SupabaseURL == "" {
		return result, fmt.Errorf("telemetry: supabase URL not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	// attempted tracks the message ids already offered during THIS flush.
	//
	// Undelivered rows stay in the queue by design, and GetPending is ordered by
	// (priority, id), so without this the next iteration would fetch the same
	// head rows and offer them again — burning through the per-message attempt
	// budget in a single pass and hammering a backend that just refused them.
	// Each message gets at most one attempt per flush.
	attempted := make(map[int64]bool)

	for i := 0; i < maxDrainIterations; i++ {
		if err := ctx.Err(); err != nil {
			break
		}

		pending, err := s.queueStore.GetPending(drainBatchSize)
		if err != nil {
			return result, fmt.Errorf("telemetry: read outbound queue: %w", err)
		}
		if len(pending) == 0 {
			break
		}

		delivered, progressed, stop, sendErr := s.deliverBatch(ctx, pending, &result, attempted)

		// Confirmed deliveries are removed first, then their sections are
		// advanced. Doing it in this order means a delete failure leaves the
		// reconcile clock untouched, so the message is simply re-sent rather
		// than being marked delivered while still queued.
		if len(delivered) > 0 {
			if err := s.commitDelivered(delivered, &result); err != nil {
				return result, err
			}
		}

		if sendErr != nil {
			return result, sendErr
		}
		if stop || !progressed {
			// Nothing new was attempted, so another iteration would only re-read
			// the same rows. Whatever remains waits for the next cycle.
			break
		}
	}

	if depth, err := s.queueStore.Depth(); err == nil {
		result.Remaining = depth
	}
	if dead, err := s.queueStore.DeadLetterDepth(); err == nil {
		result.DeadLetterDepth = dead
	}

	if result.Delivered > 0 || result.Rejected > 0 || result.DeadLettered > 0 {
		log.Printf("[telemetry] flush: delivered=%d rejected=%d dead_lettered=%d remaining=%d dead_letter_total=%d",
			result.Delivered, result.Rejected, result.DeadLettered,
			result.Remaining, result.DeadLetterDepth)
	}
	return result, nil
}

// deliverBatch offers each not-yet-attempted message in turn.
//
// It returns the messages the backend acknowledged, whether any new message was
// attempted, whether the drain should stop, and any error that must propagate
// (auth, or a transient failure that survived the retry policy).
func (s *Service) deliverBatch(
	ctx context.Context,
	pending []store.OutboundMessage,
	result *FlushResult,
	attempted map[int64]bool,
) (delivered []store.OutboundMessage, progressed bool, stop bool, err error) {
	for _, msg := range pending {
		if ctx.Err() != nil {
			return delivered, progressed, true, nil
		}
		if attempted[msg.ID] {
			continue
		}
		attempted[msg.ID] = true
		progressed = true

		// Safety net. GetPending already excludes dead-lettered rows, so this
		// should not trigger; if it does, skip rather than re-send.
		if msg.DeadLettered || msg.Attempts >= maxDeliveryAttempts {
			result.Poisoned++
			continue
		}

		outcome, status, sendErr := s.postMessage(ctx, msg)
		switch outcome {
		case outcomeDelivered:
			delivered = append(delivered, msg)
			result.Delivered++

		case outcomeRejected:
			// Loud, counted, and retained. rpcutil.WithEnqueueRetry logs and
			// swallows non-auth 4xx by design; this sender deliberately does not
			// inherit that behaviour for telemetry.
			result.Rejected++
			s.recordRejection(msg, status)
			if incErr := s.queueStore.IncrementAttempts([]int64{msg.ID}); incErr != nil {
				log.Printf("[telemetry] record delivery attempt for message %d: %v", msg.ID, incErr)
			}
			if msg.Attempts+1 >= maxDeliveryAttempts {
				// Out of attempts: retain for inspection, but take it out of the
				// delivery path so it cannot starve the queue behind it.
				if dlErr := s.queueStore.MarkDeadLettered([]int64{msg.ID}); dlErr != nil {
					log.Printf("[telemetry] dead-letter message %d: %v", msg.ID, dlErr)
				} else {
					result.DeadLettered++
				}
			}

		case outcomeAuth:
			// Stop and surface: the caller recovers the session and retries.
			return delivered, progressed, true, sendErr

		case outcomeTransient:
			// The backend is unreachable or failing. Stop the drain and keep
			// everything queued for the next cycle.
			if incErr := s.queueStore.IncrementAttempts([]int64{msg.ID}); incErr != nil {
				log.Printf("[telemetry] record delivery attempt for message %d: %v", msg.ID, incErr)
			}
			return delivered, progressed, true, sendErr
		}
	}
	return delivered, progressed, false, nil
}

// commitDelivered removes acknowledged messages and then advances the reconcile
// clock for exactly the sections they carried.
func (s *Service) commitDelivered(delivered []store.OutboundMessage, result *FlushResult) error {
	ids := make([]int64, 0, len(delivered))
	for _, m := range delivered {
		ids = append(ids, m.ID)
	}

	if err := s.queueStore.Delete(ids); err != nil {
		// Matching the audit-log queue discipline: do not continue after a
		// delete failure, or the same rows are fetched again next iteration and
		// re-uploaded in a tight loop.
		return fmt.Errorf("telemetry: delete delivered messages: %w", err)
	}

	now := time.Now().UTC()
	for _, m := range delivered {
		sections := SectionsOf(m)
		s.domain.MarkDelivered(sections, now)
		for _, name := range sections {
			if !containsSection(result.Sections, name) {
				result.Sections = append(result.Sections, name)
			}
		}
	}
	return nil
}

// postMessage sends one queued message and classifies the result.
//
// The status code is captured inside the closure because
// rpcutil.WithEnqueueRetry returns nil after logging a non-auth 4xx — its
// "server rejected the payload, dropping" path. Telemetry must not be dropped
// silently, so the recorded status is what decides the outcome, not the
// returned error. It is also returned directly (not parsed back out of an
// error string) so callers like recordRejection never need to touch response
// content to know why a message was rejected.
func (s *Service) postMessage(ctx context.Context, msg store.OutboundMessage) (deliveryOutcome, int, error) {
	url := s.cfg.SupabaseURL + rpcEnqueueTelemetry
	accessToken := s.cfg.GetAccessToken()
	anonKey := s.cfg.SupabaseKey

	// The stored payload is already the complete {"payload": {...}} body, so a
	// retry replays identical bytes — including snapshot_id, batch_index and
	// batch_count. The backend therefore never sees a second logical snapshot
	// for one collection.
	body := []byte(msg.Payload)

	var lastStatus int
	err := rpcutil.WithEnqueueRetry(ctx, func(ctx context.Context) (int, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if reqErr != nil {
			return 0, fmt.Errorf("create request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("apikey", anonKey)

		resp, doErr := s.client.Do(req)
		if doErr != nil {
			lastStatus = 0
			return 0, doErr
		}
		defer func() { _ = resp.Body.Close() }()

		lastStatus = resp.StatusCode
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			// The response body is deliberately never included in this error:
			// it is the backend's own rejection text, and a Postgres/PostgREST
			// constraint or validation error routinely echoes back the
			// offending submitted value. This error's text is also what the
			// shared enqueue retry policy (rpcutil.WithEnqueueRetry) logs
			// verbatim for its own "server rejected payload" line, so keeping
			// it body-free protects that log line too, not just this one.
			// Status code and response size are the safe, sufficient triage
			// signal; the full outbound payload is separately recoverable from
			// local queue/dead-letter storage if deeper inspection is needed.
			return resp.StatusCode, fmt.Errorf("HTTP %d (%d byte response)", resp.StatusCode, len(respBody))
		}

		var enqResp rpcutil.EnqueueResponse
		if jsonErr := json.Unmarshal(respBody, &enqResp); jsonErr != nil {
			log.Printf("[telemetry] enqueue accepted but response parse failed: %v", jsonErr)
		} else {
			log.Printf("[telemetry] enqueued: msg_id=%d queue=%s", enqResp.MsgID, enqResp.Queue)
		}
		return resp.StatusCode, nil
	})

	if err != nil {
		if lastStatus == http.StatusUnauthorized {
			return outcomeAuth, lastStatus, err
		}
		return outcomeTransient, lastStatus, err
	}

	// A nil error with a 4xx status means the retry policy dropped it. Convert
	// that back into an explicit rejection so the message is retained.
	if lastStatus >= 400 && lastStatus < 500 {
		return outcomeRejected, lastStatus, fmt.Errorf("backend rejected telemetry payload (HTTP %d)", lastStatus)
	}

	return outcomeDelivered, lastStatus, nil
}

// recordRejection makes a refused payload impossible to miss.
//
// It logs only sanitized, bounded rejection metadata — message id, section
// list (already run through sanitize.ForLog), batch position, byte size,
// attempt count, and the HTTP status code. It deliberately takes an int
// rather than an error: an error's text is free-form and, upstream of this
// function, can only ever originate from a backend HTTP response (see
// postMessage), so accepting one here would leave this call's safety
// dependent on every caller, present and future, constructing that error
// correctly. Taking the status code directly makes the guarantee structural
// instead.
func (s *Service) recordRejection(msg store.OutboundMessage, httpStatus int) {
	sections := msg.Section
	log.Printf("[telemetry] backend REJECTED message id=%d sections=%s batch=%d/%d bytes=%d attempts=%d status=%d",
		msg.ID, sanitize.ForLog(sections), msg.BatchIndex+1, msg.BatchCount,
		msg.ByteSize, msg.Attempts+1, httpStatus)

	// Record once, as the message crosses the attempt threshold, so a persistent
	// backend contract mismatch surfaces without flooding the emergency log.
	if msg.Attempts+1 == maxDeliveryAttempts {
		emergencylog.Record("telemetry",
			"backend rejected telemetry message for sections %s after %d attempts (last HTTP status %d); "+
				"message dead-lettered and retained locally for inspection",
			sanitize.ForLog(sections), maxDeliveryAttempts, httpStatus)
	}
}

func containsSection(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// newHTTPClient returns the HTTP client used for telemetry uploads.
func newHTTPClient() *http.Client { return httpx.NewClient(rpcTimeout) }
