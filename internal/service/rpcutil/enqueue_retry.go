package rpcutil

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/supabase"
)

// enqueueRetryBase and enqueueRetryMax are vars (not consts) so tests can
// shrink them for fast, deterministic backoff assertions.
var (
	enqueueRetryBase = 1 * time.Second
	enqueueRetryMax  = 5 * time.Minute
)

// ErrPayloadDropped marks an enqueue whose payload the server rejected with a
// non-retryable 4xx. WithEnqueueRetry returns it (wrapping the server error)
// only when ctx was prepared with ReportDroppedPayloads; otherwise the drop is
// logged and nil is returned, which is what the background loops rely on.
var ErrPayloadDropped = errors.New("enqueue: server rejected payload")

type reportDropsKey struct{}

// ReportDroppedPayloads returns a ctx under which WithEnqueueRetry (and so
// PostEnqueue) reports a dropped payload as an error wrapping
// ErrPayloadDropped instead of returning nil. It is for interactive callers,
// such as the CLI, that must not report success when nothing was saved.
func ReportDroppedPayloads(ctx context.Context) context.Context {
	return context.WithValue(ctx, reportDropsKey{}, true)
}

func reportsDrops(ctx context.Context) bool {
	v, _ := ctx.Value(reportDropsKey{}).(bool)
	return v
}

// WithEnqueueRetry applies the agent-enqueue retry policy to fn:
//   - nil                 → success
//   - 401 / expired JWT   → error propagated (caller's DoWithAuthRetry handles it)
//   - 408, 429            → transient: retried like 5xx; a 429's Retry-After is honoured
//   - other 4xx           → logged and dropped (server rejected the payload; retrying won't help);
//     nil is returned, or an error wrapping ErrPayloadDropped under ReportDroppedPayloads
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
		if status >= 400 && status < 500 && !isTransient4xx(status) {
			log.Printf("[enqueue] server rejected payload (HTTP %d), dropping: %v", status, err)
			if reportsDrops(ctx) {
				return fmt.Errorf("%w (HTTP %d): %w", ErrPayloadDropped, status, err)
			}
			return nil
		}
		// 408/429, 5xx or network error (status == 0): backoff and retry.
		delay := retryDelay(attempt, status, err)
		log.Printf("[enqueue] transient error (HTTP %d), retrying in %s: %v",
			status, delay.Round(time.Millisecond), err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("enqueue retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}
	}
}

// isTransient4xx reports whether a 4xx status means "try again later" rather
// than "this payload is wrong": 408 Request Timeout and 429 Too Many Requests.
// Dropping those would silently lose payloads under backend rate limiting.
func isTransient4xx(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// retryDelay is the wait before the next attempt: the server's Retry-After on
// a 429 (capped at enqueueRetryMax), otherwise exponential backoff.
func retryDelay(attempt, status int, err error) time.Duration {
	if status == http.StatusTooManyRequests {
		if ra, ok := supabase.RetryAfter(err); ok {
			return min(ra, enqueueRetryMax)
		}
	}
	return computeEnqueueBackoff(attempt)
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
