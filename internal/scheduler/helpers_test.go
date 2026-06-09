package scheduler_test

import (
	"testing"

	"sentinelgo/internal/config"
)

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
		AccessToken: "test-token",
		AutoUpdate:  false,
	}
}
