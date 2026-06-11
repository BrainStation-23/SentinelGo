package auth

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"sentinelgo/internal/config"
	authsvc "sentinelgo/internal/service/auth"
)

// EnhancedAuth provides authentication with circuit breaker and exponential backoff
type EnhancedAuth struct {
	circuitBreaker *CircuitBreaker
	mu             sync.RWMutex
	lastTokenCheck time.Time
}

// NewEnhancedAuth creates a new enhanced authentication service
func NewEnhancedAuth() *EnhancedAuth {
	return &EnhancedAuth{
		circuitBreaker: NewCircuitBreaker("auth-service", 5, 5*time.Minute),
		lastTokenCheck: time.Time{},
	}
}

// tokenRefreshSkew is how far before the JWT's expiry a preemptive refresh is
// triggered.
const tokenRefreshSkew = 5 * time.Minute

// ValidateAndRefreshTokens validates current tokens and refreshes if needed
func (ea *EnhancedAuth) ValidateAndRefreshTokens(ctx context.Context, cfg *config.Config, tokenRefreshFunc func(context.Context, *config.Config) error) error {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	// Check if we need to validate tokens (don't check too frequently). Read the
	// previous check time BEFORE stamping the new one — the old code stamped it
	// first, which made the expiry branch below permanently unreachable.
	if !ea.lastTokenCheck.IsZero() && time.Since(ea.lastTokenCheck) < 30*time.Second {
		return nil
	}
	ea.lastTokenCheck = time.Now()

	log.Printf("Validating authentication tokens")

	// Pre-emptive refresh if the token is at/near expiration.
	if ea.shouldRefreshToken(cfg) {
		log.Printf("Token at/near expiration, attempting preemptive refresh")
		return ea.refreshWithRetry(ctx, cfg, tokenRefreshFunc)
	}

	return nil
}

// shouldRefreshToken determines if the token should be refreshed preemptively,
// based on the JWT's actual `exp` claim rather than a time-since-last-check
// guess.
func (ea *EnhancedAuth) shouldRefreshToken(cfg *config.Config) bool {
	return authsvc.ShouldRefresh(cfg.AccessToken, tokenRefreshSkew)
}

// refreshWithRetry attempts to refresh token with exponential backoff
func (ea *EnhancedAuth) refreshWithRetry(ctx context.Context, cfg *config.Config, tokenRefreshFunc func(context.Context, *config.Config) error) error {
	return ea.circuitBreaker.Execute(ctx, func() error {
		return ea.withExponentialBackoff(ctx, func(attempt int) error {
			log.Printf("Token refresh attempt %d/%d", attempt+1, 3)

			err := tokenRefreshFunc(ctx, cfg)
			if err != nil {
				log.Printf("Token refresh attempt %d failed: %v", attempt+1, err)
				return err
			}

			log.Printf("Token refresh successful on attempt %d", attempt+1)
			return nil
		})
	})
}

// withExponentialBackoff implements exponential backoff retry logic
func (ea *EnhancedAuth) withExponentialBackoff(ctx context.Context, fn func(int) error) error {
	maxAttempts := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate delay with exponential backoff and jitter
			delay := time.Duration(float64(baseDelay) * math.Pow(2, float64(attempt-1)))
			jitter := time.Duration(float64(delay) * 0.1 * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0)) // ±10% jitter
			delay += jitter

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				log.Printf("Retrying after %v delay (attempt %d/%d)", delay, attempt+1, maxAttempts)
			}
		}

		if err := fn(attempt); err != nil {
			if attempt == maxAttempts-1 {
				// Last attempt failed
				return fmt.Errorf("token refresh failed after %d attempts: %w", maxAttempts, err)
			}
			continue
		}

		// Success on this attempt
		return nil
	}

	return fmt.Errorf("unexpected error in retry logic")
}

// IsHealthy returns the current health status of the authentication service
func (ea *EnhancedAuth) IsHealthy() bool {
	stats := ea.circuitBreaker.GetStats()
	return stats.State != StateOpen
}

// GetStats returns authentication service statistics
func (ea *EnhancedAuth) GetStats() AuthStats {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	cbStats := ea.circuitBreaker.GetStats()
	return AuthStats{
		CircuitBreakerStats: cbStats,
		LastTokenCheck:      ea.lastTokenCheck,
	}
}

// AuthStats provides statistics about the authentication service
type AuthStats struct {
	CircuitBreakerStats CircuitBreakerStats
	LastTokenCheck      time.Time
}

// ValidateConfig validates required configuration fields
func ValidateConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if cfg.SupabaseURL == "" {
		return fmt.Errorf("supabase_url is required")
	}

	if cfg.DeviceID == "" {
		return fmt.Errorf("device_id is required")
	}

	// Validate URL format
	if !isValidURL(cfg.SupabaseURL) {
		return fmt.Errorf("supabase_url is not a valid URL")
	}

	// Validate intervals
	if cfg.GetSoftwareInfoUpdateInterval() <= 0 {
		return fmt.Errorf("update_interval must be positive")
	}

	if cfg.GetLogFlushInterval() <= 0 {
		return fmt.Errorf("log_flush_interval must be positive")
	}

	return nil
}

// isValidURL performs basic URL validation
func isValidURL(url string) bool {
	// Basic validation - check for required components
	if len(url) < 10 {
		return false
	}

	// Check for http/https prefix
	if url[:7] != "http://" && url[:8] != "https://" {
		return false
	}

	return true
}
