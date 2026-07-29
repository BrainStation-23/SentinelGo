package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

// epmAuditChunkSize is deliberately equal to the Uploader's internal
// maxBatchSize (see uploader.go). Upload() attempts every batch and only
// reports an aggregate total, not which rows succeeded; keeping the chunk at
// or below maxBatchSize guarantees Upload() runs exactly one batch per call,
// so its return is unambiguous: either every row in the chunk was uploaded
// (mark them all synced) or none were (mark nothing, retry next cycle).
const epmAuditChunkSize = maxBatchSize

// EPMAuditSource supplies unsynced EPM elevation-audit rows and marks them
// synced after a successful upload. *store.EPMStore implements this
// interface — internal/logging already depends on internal/store for
// *store.AuditLogStore, so referencing store.EPMAuditRow here introduces no
// new package dependency.
type EPMAuditSource interface {
	GetUnsyncedAuditLogs(limit int) ([]store.EPMAuditRow, error)
	MarkAuditLogSynced(ids []int64) error
}

// EPMAuditUploader ships EPM elevation-audit rows through the shared audit-log
// Uploader without requiring the full collect→parse→store logging pipeline.
//
// It exists because EPM elevation audit and OS audit-log collection are
// independently configurable: a deployment can reasonably run EPM with
// audit_logs_enabled=false, and previously that combination silently dropped
// EPM audit on the floor — rows accumulated in SQLite forever and never
// reached the backend. Only the upload half of the pipeline is actually needed
// here, so this type takes just that.
type EPMAuditUploader struct {
	cfg      *config.Config
	uploader *Uploader
}

// NewEPMAuditUploader builds a standalone EPM audit uploader. auth may be nil;
// when set (with *authsvc.Service) uploads recover the session on a 401 and
// pause while it is unrecoverable, exactly as LoggingIntegration.SetAuth does.
func NewEPMAuditUploader(cfg *config.Config, auth authRetrier) *EPMAuditUploader {
	e := &EPMAuditUploader{cfg: cfg}
	// stats is per-uploader and only read through GetStatistics on the logging
	// integration, so a private counter here is sufficient and keeps this
	// uploader from perturbing the audit-log pipeline's numbers.
	e.uploader = NewUploader(cfg, &statsCounter{})
	if auth != nil {
		e.uploader.SetAuth(auth)
	}
	return e
}

// UploadEPMAuditRows drains up to epmAuditChunkSize pending EPM
// elevation-audit rows from src and uploads them through the same
// batching/retry/auth-recovery Uploader used for OS-level audit logs (see
// uploader.go), each tagged with models.LogCategoryEPM so the backend can
// filter EPM elevation events independently (FR-5.3). Rows are marked synced
// in src only after a confirmed successful upload; on failure nothing is
// marked; the same rows are retried on the next call.
//
// This reuses the existing pipeline rather than standing up a parallel one:
// the only new code is the small conversion from epm.AuditEntry to
// models.AuditLog below.
func (e *EPMAuditUploader) UploadEPMAuditRows(ctx context.Context, src EPMAuditSource) (int, error) {
	if e == nil || src == nil {
		return 0, nil
	}

	rows, err := src.GetUnsyncedAuditLogs(epmAuditChunkSize)
	if err != nil {
		return 0, fmt.Errorf("get unsynced epm audit rows: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}

	logs := make([]models.AuditLog, len(rows))
	ids := make([]int64, len(rows))
	for i, r := range rows {
		logs[i] = epmAuditLogRecord(e.cfg, r.Entry)
		ids[i] = r.ID
	}

	uploaded, uploadErr := e.uploader.Upload(ctx, logs)
	if uploaded == 0 {
		if uploadErr != nil {
			return 0, fmt.Errorf("upload epm audit rows: %w", uploadErr)
		}
		return 0, nil
	}
	if uploaded != len(logs) {
		// Should not happen given epmAuditChunkSize <= maxBatchSize (see
		// comment above), but fail loudly rather than guess which subset of
		// ids to mark if the Uploader's batching behavior ever changes.
		return uploaded, fmt.Errorf("partial epm audit upload (%d of %d) — not marking any row synced to avoid guessing which succeeded", uploaded, len(logs))
	}

	if err := src.MarkAuditLogSynced(ids); err != nil {
		return uploaded, fmt.Errorf("mark epm audit rows synced: %w", err)
	}
	return uploaded, nil
}

// UploadEPMAuditRows drains and uploads pending EPM elevation-audit rows using
// the logging integration's own Uploader, so EPM audit shares the audit-log
// pipeline's auth handle and upload statistics when both are running.
//
// Retained with its original signature: callers that already hold a
// *LoggingIntegration keep working unchanged. Callers that do not (audit-log
// collection disabled) use NewEPMAuditUploader instead.
func (li *LoggingIntegration) UploadEPMAuditRows(ctx context.Context, src EPMAuditSource) (int, error) {
	if li == nil {
		return 0, nil
	}
	e := &EPMAuditUploader{cfg: li.cfg, uploader: li.uploader}
	return e.UploadEPMAuditRows(ctx, src)
}

// epmAuditLogRecord converts an EPM elevation-audit entry into the generic
// AuditLog shape the existing upload pipeline expects.
func epmAuditLogRecord(cfg *config.Config, entry epm.AuditEntry) models.AuditLog {
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[logging] epm audit: marshal entry %s: %v", entry.RequestID, err)
		data = []byte("{}")
	}
	return models.AuditLog{
		Timestamp:    entry.LaunchedAt.UTC().Format(time.RFC3339),
		AgentID:      cfg.DeviceID,
		DeviceID:     cfg.DeviceID,
		LogCategory:  models.LogCategoryEPM,
		EventType:    "epm_elevation_" + string(entry.Decision),
		OSType:       runtime.GOOS,
		AgentVersion: cfg.CurrentVersion,
		Severity:     epmAuditSeverity(entry.Decision),
		Source:       "epm",
		EventData:    data,
	}
}

func epmAuditSeverity(decision epm.PolicyDecision) string {
	if decision == epm.DecisionAllow {
		return "info"
	}
	return "warning"
}
