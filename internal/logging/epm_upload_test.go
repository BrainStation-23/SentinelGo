package logging

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

type stubEPMAuditSource struct {
	rows          []store.EPMAuditRow
	getErr        error
	markedIDs     []int64
	markErr       error
	getCalledWith int
}

func (s *stubEPMAuditSource) GetUnsyncedAuditLogs(limit int) ([]store.EPMAuditRow, error) {
	s.getCalledWith = limit
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.rows, nil
}

func (s *stubEPMAuditSource) MarkAuditLogSynced(ids []int64) error {
	s.markedIDs = ids
	return s.markErr
}

func testLoggingCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:           filepath.Join(dir, "config.json"),
		SupabaseURL:    "https://localhost:1", // unreachable — deterministic upload failure
		SupabaseKey:    "anon-key",
		DeviceID:       "test-device",
		CurrentVersion: "dev",
	}
}

func TestUploadEPMAuditRows_NilSourceIsNoop(t *testing.T) {
	li := newTestLoggingIntegration(t)
	uploaded, err := li.UploadEPMAuditRows(context.Background(), nil)
	if err != nil || uploaded != 0 {
		t.Errorf("UploadEPMAuditRows(nil) = (%d, %v), want (0, nil)", uploaded, err)
	}
}

func TestUploadEPMAuditRows_NoUnsyncedRows(t *testing.T) {
	li := newTestLoggingIntegration(t)
	src := &stubEPMAuditSource{}

	uploaded, err := li.UploadEPMAuditRows(context.Background(), src)
	if err != nil || uploaded != 0 {
		t.Errorf("UploadEPMAuditRows = (%d, %v), want (0, nil)", uploaded, err)
	}
	if src.getCalledWith != epmAuditChunkSize {
		t.Errorf("GetUnsyncedAuditLogs called with limit %d, want %d", src.getCalledWith, epmAuditChunkSize)
	}
	if src.markedIDs != nil {
		t.Error("MarkAuditLogSynced must not be called when there is nothing to upload")
	}
}

func TestUploadEPMAuditRows_GetErrorPropagates(t *testing.T) {
	li := newTestLoggingIntegration(t)
	wantErr := errors.New("disk error")
	src := &stubEPMAuditSource{getErr: wantErr}

	_, err := li.UploadEPMAuditRows(context.Background(), src)
	if err == nil || !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped getErr, got %v", err)
	}
}

func TestUploadEPMAuditRows_UploadFailureDoesNotMarkSynced(t *testing.T) {
	li := newTestLoggingIntegration(t)
	src := &stubEPMAuditSource{
		rows: []store.EPMAuditRow{
			{ID: 1, Entry: epm.AuditEntry{RequestID: "req-1", UserID: "alice", Decision: epm.DecisionAllow, LaunchedAt: time.Now()}},
		},
	}

	// A network-level failure here goes through rpcutil.WithEnqueueRetry,
	// which retries with backoff until ctx is cancelled rather than giving up
	// on its own — so this test must bound the context itself, or it hangs.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	uploaded, err := li.UploadEPMAuditRows(ctx, src)
	if uploaded != 0 {
		t.Errorf("uploaded = %d, want 0 on network failure", uploaded)
	}
	if err == nil {
		t.Error("expected an error when the upload endpoint is unreachable")
	}
	if src.markedIDs != nil {
		t.Error("MarkAuditLogSynced must not be called when upload fails")
	}
}

func TestEpmAuditLogRecord_FieldMapping(t *testing.T) {
	cfg := &config.Config{DeviceID: "device-1", CurrentVersion: "1.2.3"}
	launchedAt := time.Date(2024, 5, 1, 10, 30, 0, 0, time.UTC)
	entry := epm.AuditEntry{
		RequestID:  "req-1",
		UserID:     "alice",
		AppPath:    "/usr/bin/tool",
		AppHash:    "abc123",
		Decision:   epm.DecisionDeny,
		PolicyID:   "rule-1",
		LaunchedAt: launchedAt,
	}

	rec := epmAuditLogRecord(cfg, entry)

	if rec.LogCategory != models.LogCategoryEPM {
		t.Errorf("LogCategory = %q, want %q", rec.LogCategory, models.LogCategoryEPM)
	}
	if rec.DeviceID != "device-1" || rec.AgentID != "device-1" {
		t.Errorf("DeviceID/AgentID = %q/%q, want device-1", rec.DeviceID, rec.AgentID)
	}
	if rec.AgentVersion != "1.2.3" {
		t.Errorf("AgentVersion = %q, want 1.2.3", rec.AgentVersion)
	}
	if rec.EventType != "epm_elevation_deny" {
		t.Errorf("EventType = %q, want epm_elevation_deny", rec.EventType)
	}
	if rec.Severity != "warning" {
		t.Errorf("Severity = %q, want warning for a denied elevation", rec.Severity)
	}
	if rec.Timestamp != "2024-05-01T10:30:00Z" {
		t.Errorf("Timestamp = %q, want 2024-05-01T10:30:00Z", rec.Timestamp)
	}

	var decoded epm.AuditEntry
	if err := json.Unmarshal(rec.EventData, &decoded); err != nil {
		t.Fatalf("EventData did not round-trip as valid JSON: %v", err)
	}
	if decoded.RequestID != entry.RequestID {
		t.Errorf("decoded RequestID = %q, want %q", decoded.RequestID, entry.RequestID)
	}
}

func TestEpmAuditSeverity(t *testing.T) {
	if got := epmAuditSeverity(epm.DecisionAllow); got != "info" {
		t.Errorf("severity for allow = %q, want info", got)
	}
	if got := epmAuditSeverity(epm.DecisionDeny); got != "warning" {
		t.Errorf("severity for deny = %q, want warning", got)
	}
}

func newTestLoggingIntegration(t *testing.T) *LoggingIntegration {
	t.Helper()
	li, err := NewLoggingIntegration(testLoggingCfg(t))
	if err != nil {
		t.Fatalf("NewLoggingIntegration: %v", err)
	}
	// UploadEPMAuditRows only needs li.uploader/li.cfg (set at construction),
	// not the collection loops themselves, but NewLoggingIntegration opens
	// the AuditLogStore's SQLite file immediately and Stop() only closes it
	// once Start() has run — so the integration must be started here purely
	// to make Stop()'s cleanup actually release the file handle before the
	// temp dir is removed.
	if err := li.Start(context.Background()); err != nil {
		t.Fatalf("LoggingIntegration.Start: %v", err)
	}
	t.Cleanup(func() { _ = li.Stop() })
	return li
}
