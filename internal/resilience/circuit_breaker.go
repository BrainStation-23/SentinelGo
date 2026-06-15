// Package resilience provides small, dependency-free building blocks for making
// a long-running agent resilient to flaky external services. It lives in its
// own package (importing nothing beyond the standard library) so both the
// low-level auth service and higher-level orchestration can depend on it
// without creating an import cycle.
package resilience

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of the circuit breaker.
type CircuitBreakerState int

const (
	// StateClosed lets calls through; failures are counted.
	StateClosed CircuitBreakerState = iota
	// StateOpen blocks calls until the reset timeout elapses.
	StateOpen
	// StateHalfOpen lets a single trial call through to probe recovery.
	StateHalfOpen
)

// String renders the state for logs.
func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for external service
// calls. After maxFailures consecutive failures it opens and rejects calls for
// resetTimeout, then allows a single trial (half-open) before closing again.
type CircuitBreaker struct {
	name         string
	maxFailures  int
	resetTimeout time.Duration
	mu           sync.RWMutex
	state        CircuitBreakerState
	failures     int
	lastFailTime time.Time
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Execute runs fn if the breaker allows it. When the breaker is open it returns
// an error WITHOUT calling fn — this is what throttles a permanently failing
// dependency from being hammered every tick.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !cb.canExecute() {
		return fmt.Errorf("circuit breaker %s is OPEN", cb.name)
	}

	err := fn()
	cb.recordResult(err)
	return err
}

// canExecute checks if the operation should be allowed.
func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Allow a single trial call once the reset timeout has elapsed.
		if time.Since(cb.lastFailTime) > cb.resetTimeout {
			cb.state = StateHalfOpen
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

// recordResult updates the breaker state based on the call outcome.
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		// Success - reset failure count and close circuit.
		cb.failures = 0
		cb.state = StateClosed
		return
	}

	// Failure - increment failure count.
	cb.failures++
	cb.lastFailTime = time.Now()

	if cb.failures >= cb.maxFailures {
		cb.state = StateOpen
	}
}

// GetState returns the current state of the circuit breaker.
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns a snapshot of circuit breaker statistics.
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return CircuitBreakerStats{
		Name:         cb.name,
		State:        cb.state,
		Failures:     cb.failures,
		LastFailTime: cb.lastFailTime,
	}
}

// CircuitBreakerStats provides a point-in-time view of the breaker.
type CircuitBreakerStats struct {
	Name         string
	State        CircuitBreakerState
	Failures     int
	LastFailTime time.Time
}
