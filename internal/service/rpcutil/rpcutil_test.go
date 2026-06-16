package rpcutil

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCallWithTimeout_Fast(t *testing.T) {
	got, err := CallWithTimeout(context.Background(), time.Second, func() (string, error) {
		return "ok", nil
	})
	if err != nil || got != "ok" {
		t.Fatalf("got (%q, %v), want (\"ok\", nil)", got, err)
	}
}

func TestCallWithTimeout_PropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := CallWithTimeout(context.Background(), time.Second, func() (string, error) {
		return "", sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapping %v", err, sentinel)
	}
}

func TestCallWithTimeout_TimesOut(t *testing.T) {
	start := time.Now()
	_, err := CallWithTimeout(context.Background(), 50*time.Millisecond, func() (string, error) {
		time.Sleep(2 * time.Second) // simulates a hung RPC
		return "late", nil
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("CallWithTimeout blocked %s, should have returned at ~50ms", elapsed)
	}
}

func TestWithEnqueueRetryClassified_Rejects4xx(t *testing.T) {
	err := WithEnqueueRetryClassified(context.Background(), func(_ context.Context) (int, error) {
		return 400, errors.New("bad request")
	})
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("expected *RejectedError for a 4xx, got %v", err)
	}
	if rej.Status != 400 {
		t.Errorf("RejectedError.Status = %d, want 400", rej.Status)
	}
}

func TestWithEnqueueRetryClassified_Propagates401(t *testing.T) {
	sentinel := errors.New("unauthorized")
	err := WithEnqueueRetryClassified(context.Background(), func(_ context.Context) (int, error) {
		return 401, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("401 should propagate the underlying error, got %v", err)
	}
	var rej *RejectedError
	if errors.As(err, &rej) {
		t.Error("401 must not be classified as a RejectedError")
	}
}

func TestWithEnqueueRetryClassified_SuccessIsNil(t *testing.T) {
	if err := WithEnqueueRetryClassified(context.Background(), func(_ context.Context) (int, error) {
		return 200, nil
	}); err != nil {
		t.Fatalf("2xx should return nil, got %v", err)
	}
}

// TestWithEnqueueRetry_Drops4xx confirms the legacy wrapper still logs-and-drops a 4xx
// (returns nil), preserving behaviour for its non-audit callers.
func TestWithEnqueueRetry_Drops4xx(t *testing.T) {
	if err := WithEnqueueRetry(context.Background(), func(_ context.Context) (int, error) {
		return 422, errors.New("unprocessable")
	}); err != nil {
		t.Fatalf("WithEnqueueRetry should drop a 4xx (return nil), got %v", err)
	}
}
