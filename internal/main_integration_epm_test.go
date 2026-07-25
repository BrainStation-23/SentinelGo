package internal

// White-box tests for the Phase 4 EPM scheduler wiring (epm-policy-sync and
// epm-audit-sync scheduler tasks). Package internal (not internal_test) is
// required to reach the unexported handler builders.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/scheduler"
	"sentinelgo/internal/store"
)

func testEPMCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        filepath.Join(dir, "config.json"),
		SupabaseURL: "https://localhost:1", // unreachable — triggers fast failure, no real network
		SupabaseKey: "anon-key",
		DeviceID:    "test-device",
		EPMEnabled:  true,
	}
}

func TestBuildEPMPolicySyncTask_Shape(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	task := mi.buildEPMPolicySyncTask()

	if task.Name != "epm-policy-sync" {
		t.Errorf("Name = %q, want epm-policy-sync", task.Name)
	}
	if !task.Enabled {
		t.Error("expected task to be enabled")
	}
	if task.Interval != mi.cfg.GetEPMPolicySyncInterval() {
		t.Errorf("Interval = %v, want %v", task.Interval, mi.cfg.GetEPMPolicySyncInterval())
	}
	if task.Handler == nil {
		t.Error("expected non-nil handler")
	}
}

func TestEPMPolicySyncHandler_DisabledIsNoop(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	handler := mi.epmPolicySyncHandler()

	cfg := &config.Config{EPMEnabled: false}
	if err := handler(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected nil error when EPM disabled, got %v", err)
	}
}

func TestEPMPolicySyncHandler_FetchFailureReturnsError(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	handler := mi.epmPolicySyncHandler()

	cfg := testEPMCfg(t)
	// No real Supabase reachable at this URL: GetTasks must fail, and the
	// handler must surface that as an error rather than panicking.
	if err := handler(context.Background(), cfg, nil); err == nil {
		t.Error("expected an error when the task-fetch RPC is unreachable")
	}
}

func TestBuildEPMAuditSyncTask_NilWhenLoggingDisabled(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	// mi.loggingService is nil (never started in this test).
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	task := mi.buildEPMAuditSyncTask(s)
	if task != nil {
		t.Error("expected nil task when logging service is not running")
	}
}

func TestBuildEPMAuditSyncTask_Shape(t *testing.T) {
	cfg := testEPMCfg(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())

	li := newStartedLoggingIntegration(t, cfg)
	mi.loggingService = li

	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	task := mi.buildEPMAuditSyncTask(s)
	if task == nil {
		t.Fatal("expected a non-nil task when logging service is running")
	}
	if task.Name != "epm-audit-sync" {
		t.Errorf("Name = %q, want epm-audit-sync", task.Name)
	}
	if task.Interval != cfg.GetLogFlushInterval() {
		t.Errorf("Interval = %v, want %v", task.Interval, cfg.GetLogFlushInterval())
	}
}

func TestEPMAuditSyncHandler_DisabledIsNoop(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	handler := mi.epmAuditSyncHandler(s)
	cfg := &config.Config{EPMEnabled: false}
	if err := handler(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected nil error when EPM disabled, got %v", err)
	}
}

func TestEPMAuditSyncHandler_NoLoggingServiceIsNoop(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	// mi.loggingService intentionally left nil.
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	handler := mi.epmAuditSyncHandler(s)
	cfg := testEPMCfg(t)
	if err := handler(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected nil error when logging service is absent, got %v", err)
	}
}

func TestEPMAuditSyncHandler_NoUnsyncedRowsIsNoop(t *testing.T) {
	cfg := testEPMCfg(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())

	li := newStartedLoggingIntegration(t, cfg)
	mi.loggingService = li

	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	handler := mi.epmAuditSyncHandler(s)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := handler(ctx, cfg, nil); err != nil {
		t.Errorf("expected nil error with no unsynced rows, got %v", err)
	}
}

// newStartedLoggingIntegration returns a started *logging.LoggingIntegration
// and registers a t.Cleanup to stop it. NewLoggingIntegration opens a SQLite
// file immediately on construction; that handle is only released by Stop(),
// which itself only closes anything once the integration has been Start()ed
// — so tests must start (not just construct) it, or the temp-dir cleanup
// fails on Windows with the DB file still open.
func newStartedLoggingIntegration(t *testing.T, cfg *config.Config) *logging.LoggingIntegration {
	t.Helper()
	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration: %v", err)
	}
	if err := li.Start(context.Background()); err != nil {
		t.Fatalf("LoggingIntegration.Start: %v", err)
	}
	t.Cleanup(func() { _ = li.Stop() })
	return li
}
