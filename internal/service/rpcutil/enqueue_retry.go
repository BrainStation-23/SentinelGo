package rpcutil

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"sentinelgo/internal/supabase"
)

// enqueueRetryBase and enqueueRetryMax are vars (not consts) so tests can
// shrink them for fast, deterministic backoff assertions.
var (
	enqueueRetryBase = 1 * time.Second
	enqueueRetryMax  = 5 * time.Minute
)

// WithEnqueueRetry applies the agent-enqueue retry policy to fn:
//   - nil                 → success
//   - 401 / expired JWT   → error propagated (caller's DoWithAuthRetry handles it)
//   - other 4xx           → logged and dropped (server rejected the payload; retrying won't help)
//   - 5xx or network      → exponential backoff + jitter (1 s initial, 5 min max delay),
//     retried until ctx is cancelled
//
// The HTTP status is read from the *supabase.APIError in fn's error chain; an
// error without one (network failure, timeout) counts as transient.
func WithEnqueueRetry(ctx context.Context, fn func(ctx context.Context) error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(ctx)
		if err == nil {
			return nil
		}
		status := supabase.StatusCode(err)
		if status == 401 || supabase.IsUnauthorized(err) {
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
	jitter := time.Duration(cryptoInt63n(int64(d) + 1))
	if d+jitter > enqueueRetryMax {
		return enqueueRetryMax
	}
	return d + jitter
}

// cryptoInt63n returns a non-negative random int64 in [0, n) using crypto/rand.
// Falls back to n/2 (the midpoint) if the system entropy source is unavailable,
// which is a safe degradation for backoff jitter.
func cryptoInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return n / 2
	}
	return int64(binary.BigEndian.Uint64(buf[:])>>1) % n
}
