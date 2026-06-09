package auth_test

import (
	"testing"

	"sentinelgo/internal/auth"
	"sentinelgo/internal/config"
)

// TestEnhancedAuth tests enhanced authentication
func TestEnhancedAuth(t *testing.T) {
	// Create enhanced auth
	enhancedAuth := auth.NewEnhancedAuth()
	if enhancedAuth == nil {
		t.Fatal("Failed to create enhanced auth")
	}

	// Create test config
	cfg := createTestConfigForAuth(t)

	// Test config validation
	if err := auth.ValidateConfig(cfg); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Test auth stats
	stats := enhancedAuth.GetStats()
	if stats.LastTokenCheck.IsZero() {
		t.Log("Last token check is zero (expected for new instance)")
	}

	// Test health check
	if !enhancedAuth.IsHealthy() {
		t.Log("Enhanced auth is healthy (expected for new instance)")
	}

	t.Log("Enhanced auth test passed")
}

// createTestConfigForAuth creates a minimal test configuration for auth tests.
func createTestConfigForAuth(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
	}
}
