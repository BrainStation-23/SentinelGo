package auth_test

import (
	"testing"
	"time"

	"sentinelgo/internal/auth"
)

func TestNewAuthLogger(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")
	if logger == nil {
		t.Fatal("NewAuthLogger() returned nil")
	}
}

func TestAuthLogger_LogAuthEvent(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogAuthEvent("test_event", "test message", map[string]interface{}{
		"key": "value",
	})
}

func TestAuthLogger_LogTokenRefresh(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogTokenRefresh(1, 3, true, nil)
	logger.LogTokenRefresh(2, 3, false, nil)
}

func TestAuthLogger_LogCircuitBreakerStateChange(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogCircuitBreakerStateChange("closed", "open", 3)
}

func TestAuthLogger_LogAuthFailure(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogAuthFailure("invalid_token", "token expired")
}

func TestAuthLogger_LogAuthSuccess(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogAuthSuccess("successful authentication")
}

func TestAuthLogger_LogTokenExpiry(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	// These should not panic
	logger.LogTokenExpiry(5 * time.Minute)
}

func TestAuthLogger_LogAuthEvent_NilMetadata(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogAuthEvent("test_event", "test message", nil)
}

func TestAuthLogger_LogAuthEvent_EmptyEvent(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogAuthEvent("", "test message", map[string]interface{}{})
}

func TestAuthLogger_LogTokenRefresh_ZeroValues(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogTokenRefresh(0, 0, false, nil)
}

func TestAuthLogger_LogAuthSuccess_EmptyMessage(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogAuthSuccess("")
}

func TestAuthLogger_LogTokenExpiry_ZeroDuration(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogTokenExpiry(0)
}

func TestAuthLogger_LogTokenExpiry_NegativeDuration(t *testing.T) {
	logger := auth.NewAuthLogger("test-prefix")

	logger.LogTokenExpiry(-1 * time.Minute)
}
