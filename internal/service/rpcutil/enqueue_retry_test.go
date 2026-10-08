package rpcutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
)

// statusErr is the error a Supabase RPC returns for an HTTP status.
func statusErr(status int, msg string) error {
	return &supabase.APIError{Status: status, Message: msg, Method: "POST", Path: "/rest/v1/rpc/agent_enqueue_test"}
}

func TestWithEnqueueRetry_Success(t *testing.T) {
	calls := 0
	err := WithEnqueueRetry(context.Background(), func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestWithEnqueueRetry_401Propagates(t *testing.T) {
	sentinel := statusErr(401, "JWT expired")
	calls := 0
	err := WithEnqueueRetry(context.Background(), func(ctx context.Context) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapping %v", err, sentinel)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 401)", calls)
	}
}

func TestWithEnqueueRetry_Other4xxDropped(t *testing.T) {
	calls := 0
	err := WithEnqueueRetry(context.Background(), func(ctx context.Context) error {
		calls++
		return statusErr(422, "unprocessable")
	})
	if err != nil {
		t.Fatalf("err = %v, want nil (4xx payload rejections are dropped)", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", calls)
	}
}

func TestWithEnqueueRetry_5xxThenSuccess(t *testing.T) {
	prevBase, prevMax := enqueueRetryBase, enqueueRetryMax
	enqueueRetryBase = time.Millisecond
	enqueueRetryMax = 10 * time.Millisecond
	t.Cleanup(func() { enqueueRetryBase, enqueueRetryMax = prevBase, prevMax })

	calls := 0
	err := WithEnqueueRetry(context.Background(), func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return statusErr(503, "service unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestWithEnqueueRetry_NetworkErrorRetries(t *testing.T) {
	prevBase, prevMax := enqueueRetryBase, enqueueRetryMax
	enqueueRetryBase = time.Millisecond
	enqueueRetryMax = 10 * time.Millisecond
	t.Cleanup(func() { enqueueRetryBase, enqueueRetryMax = prevBase, prevMax })

	calls := 0
	err := WithEnqueueRetry(context.Background(), func(ctx context.Context) error {
		calls++
		if calls < 2 {
			return errors.New("dial tcp: connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestWithEnqueueRetry_ContextCancelledBeforeCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := WithEnqueueRetry(ctx, func(ctx context.Context) error {
		calls++
		return nil
	})
	if err == nil {
		t.Fatal("expected context-cancellation error, got nil")
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0 (ctx already cancelled)", calls)
	}
}

func TestWithEnqueueRetry_ContextCancelledDuringBackoff(t *testing.T) {
	prevBase, prevMax := enqueueRetryBase, enqueueRetryMax
	enqueueRetryBase = time.Second
	enqueueRetryMax = time.Minute
	t.Cleanup(func() { enqueueRetryBase, enqueueRetryMax = prevBase, prevMax })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := WithEnqueueRetry(ctx, func(ctx context.Context) error {
		return statusErr(500, "boom")
	})
	if err == nil {
		t.Fatal("expected error when ctx is cancelled mid-backoff")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("WithEnqueueRetry blocked %s, should have returned once ctx cancelled", elapsed)
	}
}

func TestComputeEnqueueBackoff_GrowsAndCaps(t *testing.T) {
	prevBase, prevMax := enqueueRetryBase, enqueueRetryMax
	enqueueRetryBase = time.Second
	enqueueRetryMax = 5 * time.Second
	t.Cleanup(func() { enqueueRetryBase, enqueueRetryMax = prevBase, prevMax })

	d0 := computeEnqueueBackoff(0)
	if d0 < enqueueRetryBase || d0 > 2*enqueueRetryBase {
		t.Errorf("computeEnqueueBackoff(0) = %s, want within [base, 2*base]", d0)
	}

	// Large attempt counts must saturate at the cap, not overflow or loop forever.
	dCap := computeEnqueueBackoff(10)
	if dCap > enqueueRetryMax {
		t.Errorf("computeEnqueueBackoff(10) = %s, want <= max %s", dCap, enqueueRetryMax)
	}
}

func TestCryptoInt63n_ZeroOrNegative(t *testing.T) {
	if got := cryptoInt63n(0); got != 0 {
		t.Errorf("cryptoInt63n(0) = %d, want 0", got)
	}
	if got := cryptoInt63n(-5); got != 0 {
		t.Errorf("cryptoInt63n(-5) = %d, want 0", got)
	}
}

func TestCryptoInt63n_WithinRange(t *testing.T) {
	for i := 0; i < 50; i++ {
		got := cryptoInt63n(100)
		if got < 0 || got >= 100 {
			t.Fatalf("cryptoInt63n(100) = %d, want in [0, 100)", got)
		}
	}
}
