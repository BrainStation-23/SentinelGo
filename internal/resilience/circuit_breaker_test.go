package resilience_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"sentinelgo/internal/resilience"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 3, time.Minute)
	if cb.GetState() != resilience.StateClosed {
		t.Errorf("initial state = %v, want StateClosed", cb.GetState())
	}
}

func TestCircuitBreaker_SuccessNeverOpens(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 3, time.Minute)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := cb.Execute(ctx, func() error { return nil }); err != nil {
			t.Fatalf("Execute() should succeed, got: %v", err)
		}
	}

	if cb.GetState() != resilience.StateClosed {
		t.Errorf("state after 10 successes = %v, want StateClosed", cb.GetState())
	}
}

func TestCircuitBreaker_ClosedToOpen(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 3, time.Minute)
	ctx := context.Background()
	failFn := func() error { return errors.New("service error") }

	for i := 0; i < 3; i++ {
		_ = cb.Execute(ctx, failFn)
	}

	if cb.GetState() != resilience.StateOpen {
		t.Errorf("state after %d failures = %v, want StateOpen", 3, cb.GetState())
	}
}

func TestCircuitBreaker_OpenBlocksExecution(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 1, time.Minute)
	ctx := context.Background()

	_ = cb.Execute(ctx, func() error { return errors.New("fail") })
	if cb.GetState() != resilience.StateOpen {
		t.Fatal("circuit should be open after maxFailures=1 error")
	}

	calls := 0
	err := cb.Execute(ctx, func() error {
		calls++
		return nil
	})
	if err == nil {
		t.Error("Execute() on open circuit should return error, got nil")
	}
	if calls != 0 {
		t.Errorf("fn was called %d times on open circuit, want 0", calls)
	}
}

func TestCircuitBreaker_SuccessResetsToClose(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 2, time.Millisecond)
	ctx := context.Background()

	_ = cb.Execute(ctx, func() error { return errors.New("fail") })
	_ = cb.Execute(ctx, func() error { return errors.New("fail") })
	if cb.GetState() != resilience.StateOpen {
		t.Fatal("circuit should be open")
	}

	time.Sleep(10 * time.Millisecond)

	// Execute with success: Open → HalfOpen → Closed
	if err := cb.Execute(ctx, func() error { return nil }); err != nil {
		t.Fatalf("Execute() after reset timeout = %v, want nil", err)
	}

	if cb.GetState() != resilience.StateClosed {
		t.Errorf("state after HalfOpen success = %v, want StateClosed", cb.GetState())
	}
}

func TestCircuitBreaker_HalfOpen_FailureReopens(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 2, time.Millisecond)
	ctx := context.Background()

	_ = cb.Execute(ctx, func() error { return errors.New("fail") })
	_ = cb.Execute(ctx, func() error { return errors.New("fail") })

	time.Sleep(10 * time.Millisecond)

	// Execute with failure: Open → HalfOpen (fn runs, fails) → Open
	_ = cb.Execute(ctx, func() error { return errors.New("still failing") })

	if cb.GetState() != resilience.StateOpen {
		t.Errorf("state after HalfOpen failure = %v, want StateOpen", cb.GetState())
	}
}

func TestCircuitBreaker_GetStats_Initial(t *testing.T) {
	cb := resilience.NewCircuitBreaker("my-breaker", 5, time.Minute)

	stats := cb.GetStats()
	if stats.Name != "my-breaker" {
		t.Errorf("GetStats().Name = %q, want %q", stats.Name, "my-breaker")
	}
	if stats.State != resilience.StateClosed {
		t.Errorf("GetStats().State = %v, want StateClosed", stats.State)
	}
	if stats.Failures != 0 {
		t.Errorf("GetStats().Failures = %d, want 0", stats.Failures)
	}
}

func TestCircuitBreaker_GetStats_AfterFailures(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 5, time.Minute)
	ctx := context.Background()

	_ = cb.Execute(ctx, func() error { return errors.New("err") })
	_ = cb.Execute(ctx, func() error { return errors.New("err") })

	stats := cb.GetStats()
	if stats.Failures != 2 {
		t.Errorf("GetStats().Failures after 2 errors = %d, want 2", stats.Failures)
	}
	if stats.State != resilience.StateClosed {
		t.Errorf("GetStats().State after 2 errors (max=5) = %v, want StateClosed", stats.State)
	}
}

func TestCircuitBreaker_SuccessResetFailureCount(t *testing.T) {
	cb := resilience.NewCircuitBreaker("test", 3, time.Minute)
	ctx := context.Background()

	_ = cb.Execute(ctx, func() error { return errors.New("fail") })
	_ = cb.Execute(ctx, func() error { return errors.New("fail") })

	// A success should reset failure count back to 0
	_ = cb.Execute(ctx, func() error { return nil })

	stats := cb.GetStats()
	if stats.Failures != 0 {
		t.Errorf("GetStats().Failures after success = %d, want 0", stats.Failures)
	}
	if stats.State != resilience.StateClosed {
		t.Errorf("GetStats().State after success = %v, want StateClosed", stats.State)
	}
}
