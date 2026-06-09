package internal_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
)

func minimalTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
		AutoUpdate:  false,
	}
}

func TestNewMainIntegration_NilConfig(t *testing.T) {
	mi := internal.NewMainIntegration(nil)
	if mi == nil {
		t.Fatal("NewMainIntegration() should handle nil config")
	}
}

func TestNewMainIntegration_ValidConfig(t *testing.T) {
	mi := internal.NewMainIntegration(minimalTestConfig(t))
	if mi == nil {
		t.Fatal("NewMainIntegration() returned nil")
	}
}

func TestMainIntegration_GetStatus_NilConfig(t *testing.T) {
	mi := internal.NewMainIntegration(nil)

	status := mi.GetStatus()
	if status == nil {
		t.Error("GetStatus() should not return nil")
	}
	if _, exists := status["scheduler"]; !exists {
		t.Error("GetStatus() should include scheduler status")
	}
	if _, exists := status["authentication"]; !exists {
		t.Error("GetStatus() should include authentication status")
	}
}

func TestMainIntegration_GetStatus_AfterStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration Start() (slow OS collection / network) in -short mode")
	}
	mi := internal.NewMainIntegration(minimalTestConfig(t))
	if mi == nil {
		t.Fatal("NewMainIntegration() returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = mi.Start(ctx)

	status := mi.GetStatus()
	if status == nil {
		t.Error("GetStatus() should not return nil after Start")
	}
	_ = mi.Stop()
}

func TestMainIntegration_Stop_NilConfig(t *testing.T) {
	mi := internal.NewMainIntegration(nil)
	if err := mi.Stop(); err != nil {
		t.Errorf("Stop() should handle nil config: %v", err)
	}
}

func TestMainIntegration_Stop_AfterStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration Start() (slow OS collection / network) in -short mode")
	}
	mi := internal.NewMainIntegration(minimalTestConfig(t))
	if mi == nil {
		t.Fatal("NewMainIntegration() returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = mi.Start(ctx)

	if err := mi.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestMainIntegration_Start_CancelledContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration Start() (slow OS collection / network) in -short mode")
	}
	mi := internal.NewMainIntegration(minimalTestConfig(t))
	if mi == nil {
		t.Fatal("NewMainIntegration() returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_ = mi.Start(ctx)
	_ = mi.Stop()
}
