package internal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// TestMainIntegration_StartDoesNotBlockOnSlowLogin guards against the Windows
// service-start regression: agent-login can take up to loginTimeout (60s) per
// attempt across up to 3 attempts, but Start() runs inside the Windows SCM's
// synchronous Execute callback, which must report SERVICE_RUNNING within
// ServicesPipeTimeout (30s by default) or Windows kills the process (Events
// 7000/7009). Start() must therefore return promptly regardless of how slow
// or hung agent-login is; auth establishes in the background and the
// scheduler's existing Healthy()-gated tasks tolerate it not being ready yet.
func TestMainIntegration_StartDoesNotBlockOnSlowLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration Start() (slow OS collection / network) in -short mode")
	}

	// block and srv.Close() must be unwound in that exact order: Server.Close()
	// waits for outstanding requests to finish, and the handler below is
	// deliberately parked on <-block. A plain t.Cleanup fires after the test
	// function's own defers, so a separate "defer srv.Close()" would run
	// first and deadlock waiting on a handler this same cleanup hasn't
	// unblocked yet. One deferred closure keeps the order explicit.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond, simulating a hung/very slow agent-login call
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	cfg := minimalTestConfig(t)
	cfg.SupabaseURL = srv.URL
	cfg.AgentSecret = "test-secret" // required for Login() to actually dial out

	mi := internal.NewMainIntegration(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- mi.Start(ctx) }()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Start() took %v with agent-login hanging; must return in well under "+
				"the Windows SCM's 30s ServicesPipeTimeout regardless of login latency", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return within 2s while agent-login was hanging — " +
			"this is the exact Windows service-start regression (Events 7000/7009)")
	}

	_ = mi.Stop()
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
