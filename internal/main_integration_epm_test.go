package internal

// White-box tests for the Phase 4 EPM scheduler wiring (epm-policy-sync and
// epm-audit-sync scheduler tasks). Package internal (not internal_test) is
// required to reach the unexported handler builders.

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
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

// TestBuildEPMAuditSyncTask_BuiltWithoutLoggingService pins the fix for EPM
// audit rows being stranded: the task used to be skipped entirely whenever OS
// audit-log collection was disabled, so a deployment running EPM with
// audit_logs_enabled=false queued elevation records in SQLite forever and
// uploaded none of them. Only the upload half of the pipeline is required.
func TestBuildEPMAuditSyncTask_BuiltWithoutLoggingService(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	// mi.loggingService is nil (never started in this test).
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	task := mi.buildEPMAuditSyncTask(s)
	if task == nil {
		t.Fatal("expected a task even without the logging service")
	}
	if task.Name != "epm-audit-sync" {
		t.Errorf("Name = %q, want epm-audit-sync", task.Name)
	}
	if !task.Enabled || task.Handler == nil {
		t.Errorf("task must be enabled with a handler, got enabled=%v handler==nil:%v",
			task.Enabled, task.Handler == nil)
	}

	// The handler must resolve to the standalone uploader rather than nil-ing out.
	if up := mi.epmAuditUploader(); up == nil {
		t.Error("epmAuditUploader() returned nil without a logging service")
	}
	if mi.epmUploader == nil {
		t.Error("expected the standalone EPM uploader to be built and cached")
	}
}

// TestStartEPM_RegistersTasksWhenTransportFails pins the other half of the
// stranding fix: policy sync and audit upload must be scheduled even when the
// local enforcement transport cannot bind. startEPM used to return early on a
// failed Start, before registering either task, which left every such host with
// a policy cache that went permanently stale.
func TestStartEPM_RegistersTasksWhenTransportFails(t *testing.T) {
	orig := epmServiceFactory
	t.Cleanup(func() { epmServiceFactory = orig })
	epmServiceFactory = func(_ epm.RuleProvider, _ *epm.Auditor, _ epm.ServiceOptions) epmEnforcer {
		return failingEPMService{}
	}

	cfg := testEPMCfg(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())
	mi.startEPM(context.Background())
	t.Cleanup(func() {
		if mi.epmStore != nil {
			_ = mi.epmStore.Close()
		}
	})

	status := mi.scheduler.GetTaskStatus()
	for _, name := range []string{"epm-policy-sync", "epm-audit-sync"} {
		if _, ok := status[name]; !ok {
			t.Errorf("task %q was not registered after a failed transport start (registered: %v)",
				name, taskNames(status))
		}
	}
	if mi.epmService != nil {
		t.Error("epmService must stay nil when the transport failed to start")
	}
}

type failingEPMService struct{}

func (failingEPMService) Start(context.Context) error { return errors.New("transport unavailable") }
func (failingEPMService) Stop() error                 { return nil }

func taskNames(status map[string]scheduler.TaskStatus) []string {
	names := make([]string, 0, len(status))
	for n := range status {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
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

func TestBuildEPMDBMaintenanceTask_Shape(t *testing.T) {
	cfg := testEPMCfg(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())

	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	task := mi.buildEPMDBMaintenanceTask(s)
	if task == nil {
		t.Fatal("expected a non-nil task")
	}
	if task.Name != "epm-db-maintenance" {
		t.Errorf("Name = %q, want epm-db-maintenance", task.Name)
	}
	if task.Interval != 7*24*time.Hour {
		t.Errorf("Interval = %v, want 7 days", task.Interval)
	}
	if !task.Enabled || task.Handler == nil {
		t.Errorf("task must be enabled with a handler, got enabled=%v handler==nil:%v",
			task.Enabled, task.Handler == nil)
	}
}

func TestEPMDBMaintenanceTask_DisabledIsNoop(t *testing.T) {
	mi := NewMainIntegrationWith(testEPMCfg(t), scheduler.NewScheduler())
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	task := mi.buildEPMDBMaintenanceTask(s)
	cfg := &config.Config{EPMEnabled: false}
	if err := task.Handler(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected nil error when EPM disabled, got %v", err)
	}
}

// TestEPMDBMaintenanceTask_PrunesOldSyncedRowsAndVacuums exercises the
// handler end to end against a real (in-memory) EPMStore: an old synced
// audit row must be gone afterward, an old unsynced one must survive
// (never eligible regardless of age — see EPMStore.PruneAuditLog), and the
// handler itself must not error.
func TestEPMDBMaintenanceTask_PrunesOldSyncedRowsAndVacuums(t *testing.T) {
	cfg := testEPMCfg(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())

	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	old := time.Now().UTC().Add(-cfg.GetEPMAuditRetention() - 24*time.Hour)
	if err := s.InsertAuditLog(epm.AuditEntry{RequestID: "old-synced", Decision: epm.DecisionAllow, LaunchedAt: old}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	if err := s.InsertAuditLog(epm.AuditEntry{RequestID: "old-unsynced", Decision: epm.DecisionAllow, LaunchedAt: old}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	unsynced, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs: %v", err)
	}
	for _, row := range unsynced {
		if row.Entry.RequestID == "old-synced" {
			if err := s.MarkAuditLogSynced([]int64{row.ID}); err != nil {
				t.Fatalf("MarkAuditLogSynced: %v", err)
			}
		}
	}

	task := mi.buildEPMDBMaintenanceTask(s)
	if err := task.Handler(context.Background(), cfg, nil); err != nil {
		t.Fatalf("maintenance handler: %v", err)
	}

	remaining, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs after maintenance: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Entry.RequestID != "old-unsynced" {
		t.Errorf("unsynced rows after maintenance = %+v, want only old-unsynced", remaining)
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
