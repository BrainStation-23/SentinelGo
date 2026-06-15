package internal_test

import (
	"context"
	"path/filepath"
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
	// The auth service is created during Start (it depends on the validated
	// config and run context), so before Start there is no authentication status.
	if _, exists := status["authentication"]; exists {
		t.Error("GetStatus() should not include authentication status before Start")
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
	if _, exists := status["authentication"]; !exists {
		t.Error("GetStatus() should include authentication status after Start")
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

// TestMainIntegration_Start_WithAutoUpdate exercises maybeStartupUpdateCheck
// (the AutoUpdate=true branch that spawns a background goroutine).
func TestMainIntegration_Start_WithAutoUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	cfg := minimalTestConfig(t)
	cfg.AutoUpdate = true

	mi := internal.NewMainIntegration(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = mi.Start(ctx)
	_ = mi.Stop()
}

// TestMainIntegration_Start_WithAuditLogs exercises startLoggingService
// (the AuditLogsEnabled=true branch).
func TestMainIntegration_Start_WithAuditLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	cfg := minimalTestConfig(t)
	cfg.AuditLogsEnabled = true
	cfg.Path = filepath.Join(t.TempDir(), "config.json")

	mi := internal.NewMainIntegration(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = mi.Start(ctx)
	_ = mi.Stop()
}

// TestMainIntegration_Start_WithTaskPolling exercises startTaskManager
// (the EnableTaskPolling=true branch). TaskDBPath is set to a temp file so
// SQLite can be created without needing the system config directory.
func TestMainIntegration_Start_WithTaskPolling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	cfg := minimalTestConfig(t)
	cfg.EnableTaskPolling = true
	cfg.TaskDBPath = filepath.Join(t.TempDir(), "tasks.sqlite")

	mi := internal.NewMainIntegration(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = mi.Start(ctx)
	_ = mi.Stop()
}

// TestMainIntegration_Stop_WithAllComponents exercises the non-nil branches of
// Stop (taskManager != nil, loggingService != nil).
func TestMainIntegration_Stop_WithAllComponents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	tmpDir := t.TempDir()
	cfg := minimalTestConfig(t)
	cfg.AuditLogsEnabled = true
	cfg.EnableTaskPolling = true
	cfg.Path = filepath.Join(tmpDir, "config.json")
	cfg.TaskDBPath = filepath.Join(tmpDir, "tasks.sqlite")

	mi := internal.NewMainIntegration(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = mi.Start(ctx)

	if err := mi.Stop(); err != nil {
		t.Errorf("Stop() with all components: %v", err)
	}
}
