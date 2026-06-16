package rpcutil

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"
)

const (
	enqueueRetryBase = 1 * time.Second
	enqueueRetryMax  = 5 * time.Minute
)

// WithEnqueueRetry applies the agent-enqueue retry policy to fn:
//   - 2xx                  → nil (success; response parsing is best-effort)
//   - 401                  → error propagated (caller's DoWithAuthRetry handles it)
//   - other 4xx            → logged and dropped (server rejected the payload; retrying won't help)
//   - 5xx or network (0)   → exponential backoff + jitter (1 s initial, 5 min max delay),
//     retried until ctx is cancelled
//
// fn must return (httpStatusCode int, err error). Pass 0 as status for network-level
// errors where no HTTP response was received.
func WithEnqueueRetry(ctx context.Context, fn func(ctx context.Context) (int, error)) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		status, err := fn(ctx)

		if err == nil {
			return nil
		}

		if status == 401 {
			return err
		}

		if status >= 400 && status < 500 {
			log.Printf("[enqueue] server rejected payload (HTTP %d), dropping: %v", status, err)
			return nil
		}

		// 5xx or network error (status == 0): backoff and retry.
		delay := computeEnqueueBackoff(attempt)
		log.Printf("[enqueue] transient error (HTTP %d), retrying in %s: %v",
			status, delay.Round(time.Millisecond), err)

		select {
		case <-ctx.Done():
			return fmt.Errorf("enqueue retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}
	}
}

// computeEnqueueBackoff returns base*2^attempt + jitter, capped at enqueueRetryMax.
func computeEnqueueBackoff(attempt int) time.Duration {
	d := enqueueRetryBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= enqueueRetryMax {
			d = enqueueRetryMax
			break
		}
	}
	jitter := time.Duration(rand.Int63n(int64(d) + 1))
	if d+jitter > enqueueRetryMax {
		return enqueueRetryMax
	}
	return d + jitter
}
