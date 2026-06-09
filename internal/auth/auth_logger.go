package auth

import (
	"fmt"
	"log"
	"time"
)

// AuthLogger provides structured logging for authentication events
type AuthLogger struct {
	prefix string
}

// NewAuthLogger creates a new auth logger with the given prefix
func NewAuthLogger(prefix string) *AuthLogger {
	return &AuthLogger{
		prefix: prefix,
	}
}

// LogAuthEvent logs a structured authentication event
func (l *AuthLogger) LogAuthEvent(eventType, message string, metadata map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": eventType,
		"message":    message,
		"component":  l.prefix,
	}
	for k, v := range metadata {
		entry[k] = v
	}
	log.Printf("[auth] %s", formatLogEntry(entry))
}

// LogTokenRefresh logs token refresh events
func (l *AuthLogger) LogTokenRefresh(attempt int, maxAttempts int, success bool, err error) {
	metadata := map[string]interface{}{
		"attempt":      attempt,
		"max_attempts": maxAttempts,
		"success":      success,
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	eventType := "token_refresh"
	if !success {
		eventType = "token_refresh_failed"
	}
	l.LogAuthEvent(eventType, fmt.Sprintf("Token refresh %s on attempt %d/%d",
		map[bool]string{true: "succeeded", false: "failed"}[success], attempt, maxAttempts), metadata)
}

// LogCircuitBreakerStateChange logs circuit breaker state transitions
func (l *AuthLogger) LogCircuitBreakerStateChange(oldState, newState string, failures int) {
	l.LogAuthEvent("circuit_breaker_state_change",
		fmt.Sprintf("Circuit breaker state changed: %s -> %s (failures: %d)", oldState, newState, failures),
		map[string]interface{}{
			"old_state": oldState,
			"new_state": newState,
			"failures":  failures,
		})
}

// LogAuthFailure logs authentication failure events
func (l *AuthLogger) LogAuthFailure(reason, detail string) {
	l.LogAuthEvent("auth_failure", reason,
		map[string]interface{}{
			"detail": detail,
		})
}

// LogAuthSuccess logs successful authentication events
func (l *AuthLogger) LogAuthSuccess(detail string) {
	l.LogAuthEvent("auth_success", "Authentication successful",
		map[string]interface{}{
			"detail": detail,
		})
}

// LogTokenExpiry logs token expiry warnings
func (l *AuthLogger) LogTokenExpiry(ttl time.Duration) {
	l.LogAuthEvent("token_expiry_warning",
		fmt.Sprintf("Token expires in %v", ttl),
		map[string]interface{}{
			"ttl_seconds": int64(ttl.Seconds()),
		})
}

// formatLogEntry formats a log entry as a readable string
func formatLogEntry(entry map[string]interface{}) string {
	result := fmt.Sprintf("%s | %s | %s",
		entry["timestamp"],
		entry["event_type"],
		entry["message"])

	// Append metadata fields (skip the standard ones)
	skipKeys := map[string]bool{
		"timestamp":  true,
		"event_type": true,
		"message":    true,
		"component":  true,
	}
	for k, v := range entry {
		if !skipKeys[k] {
			result += fmt.Sprintf(" | %s=%v", k, v)
		}
	}
	return result
}
