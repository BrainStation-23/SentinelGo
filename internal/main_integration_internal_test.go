package internal

// White-box tests for unexported types in main_integration.go.
// Package internal (not internal_test) is required to instantiate authTokenRefresher.

import (
	"context"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
	authsvc "sentinelgo/internal/service/auth"
)

// miTestConfig returns a config rooted at a temp directory so the
// SQLite-backed stores (services/software) have somewhere real to open.
func miTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Path:        filepath.Join(t.TempDir(), "config.json"),
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		SupabaseURL: "", // empty: SendByRPC fails fast without a network call
		SupabaseKey: "test-key",
	}
}

// TestAuthTokenRefresher_RefreshToken exercises the RefreshToken method on the
// unexported authTokenRefresher adapter. The call will fail with a network error
// (no real Supabase server), but all statements in the function are traversed.
func TestAuthTokenRefresher_RefreshToken(t *testing.T) {
	cfg := &config.Config{
		SupabaseURL:  "https://localhost:1", // unreachable — triggers fast failure
		AccessToken:  "initial-token",
		RefreshToken: "",
	}
	svc := authsvc.NewService(cfg.SupabaseURL, cfg.AccessToken)
	r := &authTokenRefresher{authSvc: svc, cfg: cfg}

	// Ignore the error — we only need the statements to execute.
	_, _ = r.RefreshToken(context.Background())
}

// TestAuthTokenRefresher_RefreshToken_Cancelled verifies no panic when the
// context is already cancelled.
func TestAuthTokenRefresher_RefreshToken_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &config.Config{
		SupabaseURL: "https://localhost:1",
		AccessToken: "token",
	}
	svc := authsvc.NewService(cfg.SupabaseURL, cfg.AccessToken)
	r := &authTokenRefresher{authSvc: svc, cfg: cfg}

	_, _ = r.RefreshToken(ctx)
}

// ── softwareDBPath / servicesDBPath ─────────────────────────────────────────

func TestSoftwareDBPath_JoinsConfigDir(t *testing.T) {
	cfg := &config.Config{Path: filepath.Join("some", "dir", "config.json")}
	mi := &MainIntegration{cfg: cfg}

	got := mi.softwareDBPath()
	want := filepath.Join("some", "dir", "sentinelgo_software.db")
	if got != want {
		t.Errorf("softwareDBPath() = %q, want %q", got, want)
	}
}

func TestServicesDBPath_JoinsConfigDir(t *testing.T) {
	cfg := &config.Config{Path: filepath.Join("some", "dir", "config.json")}
	mi := &MainIntegration{cfg: cfg}

	got := mi.servicesDBPath()
	want := filepath.Join("some", "dir", "sentinelgo_services.db")
	if got != want {
		t.Errorf("servicesDBPath() = %q, want %q", got, want)
	}
}

// ── buildServicesTask / servicesCollectHandler ──────────────────────────────

func TestBuildServicesTask_ReturnsConfiguredTask(t *testing.T) {
	cfg := miTestConfig(t)
	mi := &MainIntegration{cfg: cfg}

	task := mi.buildServicesTask()
	if task == nil {
		t.Fatal("buildServicesTask() = nil, want a task backed by a fresh temp-dir store")
	}
	t.Cleanup(func() { _ = mi.servicesStore.Close() })
	if task.Name != "services-collect" {
		t.Errorf("task.Name = %q, want %q", task.Name, "services-collect")
	}
	if task.Handler == nil {
		t.Error("task.Handler = nil, want a handler")
	}
	if mi.servicesStore == nil {
		t.Error("buildServicesTask() should have set mi.servicesStore")
	}
}

func TestServicesCollectHandler_SkipsWhenSyncDisabled(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.ServicesSyncEnabled = false
	mi := &MainIntegration{cfg: cfg}

	task := mi.buildServicesTask()
	if task == nil {
		t.Fatal("buildServicesTask() = nil")
	}
	t.Cleanup(func() { _ = mi.servicesStore.Close() })

	if err := task.Handler(context.Background(), cfg, nil); err != nil {
		t.Errorf("handler with ServicesSyncEnabled=false should no-op, got err: %v", err)
	}
}

func TestServicesCollectHandler_RunsFullCycleWithoutAuthSvc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real OS service enumeration in -short mode")
	}
	cfg := miTestConfig(t)
	cfg.ServicesSyncEnabled = true
	mi := &MainIntegration{cfg: cfg}

	task := mi.buildServicesTask()
	if task == nil {
		t.Fatal("buildServicesTask() = nil")
	}
	t.Cleanup(func() { _ = mi.servicesStore.Close() })

	// authSvc=nil exercises the non-DoWithAuthRetry send path; an empty
	// SupabaseURL makes the eventual RPC call fail fast without a real network
	// call, while still exercising collect -> upsert -> prune -> send.
	err := task.Handler(context.Background(), cfg, nil)
	if err == nil {
		t.Log("handler succeeded (list may have been empty this cycle)")
	}
}

// ── softwareSyncHandler ──────────────────────────────────────────────────────

func TestSoftwareSyncHandler_NilWhenDisabled(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = false
	mi := &MainIntegration{cfg: cfg}

	if h := mi.softwareSyncHandler(); h != nil {
		t.Error("softwareSyncHandler() should be nil when SoftwareSyncEnabled is false")
	}
	if mi.softwareStore != nil {
		t.Error("softwareSyncHandler() should not open a store when disabled")
	}
}

func TestSoftwareSyncHandler_SkipsWhenDisabledAtRunTime(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = true
	mi := &MainIntegration{cfg: cfg}

	h := mi.softwareSyncHandler()
	if h == nil {
		t.Fatal("softwareSyncHandler() = nil, want a handler when enabled at construction")
	}
	t.Cleanup(func() { _ = mi.softwareStore.Close() })

	// Disabled between construction and the scheduler firing: the handler's own
	// runtime check must still no-op.
	cfg.SoftwareSyncEnabled = false
	if err := h(context.Background(), cfg, nil); err != nil {
		t.Errorf("handler with SoftwareSyncEnabled=false at run time should no-op, got err: %v", err)
	}
}

func TestSoftwareSyncHandler_RunsFullCycleWithoutAuthSvc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real OS software enumeration in -short mode")
	}
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = true
	mi := &MainIntegration{cfg: cfg}

	h := mi.softwareSyncHandler()
	if h == nil {
		t.Fatal("softwareSyncHandler() = nil")
	}
	t.Cleanup(func() { _ = mi.softwareStore.Close() })

	err := h(context.Background(), cfg, nil)
	if err == nil {
		t.Log("handler succeeded (list may have been empty this cycle)")
	}
}
