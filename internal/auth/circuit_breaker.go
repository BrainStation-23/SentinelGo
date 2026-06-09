package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for external service calls
type CircuitBreaker struct {
	name         string
	maxFailures  int
	resetTimeout time.Duration
	mu           sync.RWMutex
	state        CircuitBreakerState
	failures     int
	lastFailTime time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Execute runs the function if the circuit breaker allows it
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if !cb.canExecute() {
		return fmt.Errorf("circuit breaker %s is OPEN", cb.name)
	}

	err := fn()
	cb.recordResult(err)
	return err
}

// canExecute checks if the operation should be allowed
func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if reset timeout has passed
		if time.Since(cb.lastFailTime) > cb.resetTimeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = StateHalfOpen
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

// recordResult updates the circuit breaker state based on the result
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		// Success - reset failure count and close circuit
		cb.failures = 0
		cb.state = StateClosed
		return
	}

	// Failure - increment failure count
	cb.failures++
	cb.lastFailTime = time.Now()

	if cb.failures >= cb.maxFailures {
		cb.state = StateOpen
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns circuit breaker statistics
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

// CircuitBreakerStats provides statistics about the circuit breaker
type CircuitBreakerStats struct {
	Name         string
	State        CircuitBreakerState
	Failures     int
	LastFailTime time.Time
}
