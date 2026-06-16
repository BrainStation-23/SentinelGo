package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	auditlogsvc "sentinelgo/internal/service/auditlog"
	"sentinelgo/internal/store"
)

const (
	maxBatchSize    = 100
	maxPayloadBytes = 900_000 // 900 KB — headroom under the 1 MB enqueue limit
)

// authRetrier recovers the session on a 401 and reports auth health. It is
// satisfied by *authsvc.Service; kept as a local interface so the uploader stays
// testable without importing the auth package.
type authRetrier interface {
	DoWithAuthRetry(ctx context.Context, cfg *config.Config, fn func() error) error
	Healthy() bool
}

// Uploader sends batches of audit logs to the Supabase backend
// via AuditLogService. It handles batch sizing and size-based splitting.
type Uploader struct {
	svc   *auditlogsvc.AuditLogService
	cfg   *config.Config
	stats *statsCounter
	auth  authRetrier // optional; when set, uploads recover the session on 401
}

// NewUploader creates an uploader wrapping the given audit log service.
func NewUploader(cfg *config.Config, stats *statsCounter) *Uploader {
	return &Uploader{
		svc:   auditlogsvc.NewAuditLogService(cfg),
		cfg:   cfg,
		stats: stats,
	}
}

// SetAuth wires an auth recovery handle so batch uploads react to 401s and pause
// when the session is unrecoverable.
func (u *Uploader) SetAuth(auth authRetrier) {
	u.auth = auth
}

// Upload sends the given logs in batches to the backend
// via the agent_enqueue_audit_logs RPC function.
// Returns the total number of logs successfully uploaded.
func (u *Uploader) Upload(ctx context.Context, logs []models.AuditLog) (int, error) {
	if len(logs) == 0 {
		return 0, nil
	}
	if u.auth != nil && !u.auth.Healthy() {
		log.Printf("[uploader] auth degraded, deferring upload of %d logs until session recovers", len(logs))
		return 0, nil
	}

	totalUploaded := 0
	var lastErr error

	for i := 0; i < len(logs); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(logs) {
			end = len(logs)
		}
		batch := logs[i:end]

		if err := u.safeUploadBatch(ctx, batch); err != nil {
			lastErr = err
			u.stats.addErrors(int64(len(batch)))
			log.Printf("[uploader] batch upload failed (%d logs): %v", len(batch), err)
			continue
		}

		totalUploaded += len(batch)
		u.stats.addUploaded(int64(len(batch)))
	}

	if lastErr != nil && totalUploaded == 0 {
		return 0, fmt.Errorf("all batches failed, last error: %w", lastErr)
	}

	return totalUploaded, lastErr
}

// safeUploadBatch checks the marshalled payload size. If it exceeds maxPayloadBytes
// and the batch has more than one entry, it splits in half and uploads each half
// separately (recursively). This keeps every call under the 1 MB enqueue limit.
func (u *Uploader) safeUploadBatch(ctx context.Context, logs []models.AuditLog) error {
	if len(logs) <= 1 {
		return u.uploadBatch(ctx, logs)
	}
	data, err := json.Marshal(u.buildBatchPayload(logs))
	if err == nil && len(data) > maxPayloadBytes {
		mid := len(logs) / 2
		if err := u.safeUploadBatch(ctx, logs[:mid]); err != nil {
			return err
		}
		return u.safeUploadBatch(ctx, logs[mid:])
	}
	return u.uploadBatch(ctx, logs)
}

// uploadBatch sends one batch. Retry is handled inside SendBatchLogsWithContext
// via WithEnqueueRetry; DoWithAuthRetry wraps it for 401 recovery.
func (u *Uploader) uploadBatch(ctx context.Context, batch []models.AuditLog) error {
	batchData := u.buildBatchPayload(batch)

	if u.auth != nil {
		return u.auth.DoWithAuthRetry(ctx, u.cfg, func() error {
			return u.svc.SendBatchLogsWithContext(ctx, batchData)
		})
	}
	return u.svc.SendBatchLogsWithContext(ctx, batchData)
}

// buildBatchPayload constructs the map structure expected by SendBatchLogsWithContext.
func (u *Uploader) buildBatchPayload(logs []models.AuditLog) map[string]interface{} {
	systemLogs := make([]map[string]interface{}, 0)
	securityLogs := make([]map[string]interface{}, 0)
	networkLogs := make([]map[string]interface{}, 0)
	policyLogs := make([]map[string]interface{}, 0)
	otherLogs := make([]map[string]interface{}, 0)

	for i := range logs {
		entry := map[string]interface{}{
			"event_type":   logs[i].EventType,
			"created_at":   logs[i].Timestamp,
			"severity":     logs[i].Severity,
			"log_category": logs[i].LogCategory,
			"source":       logs[i].Source,
			"event_data":   logs[i].EventData,
		}

		switch logs[i].LogCategory {
		case models.LogCategorySystem, models.LogCategoryAgent, models.LogCategoryStorage:
			systemLogs = append(systemLogs, entry)
		case models.LogCategorySecurity, models.LogCategoryUser:
			securityLogs = append(securityLogs, entry)
		case models.LogCategoryNetwork:
			networkLogs = append(networkLogs, entry)
		case models.LogCategoryPolicy, models.LogCategoryRemote:
			policyLogs = append(policyLogs, entry)
		default:
			otherLogs = append(otherLogs, entry)
		}
	}

	logGroups := []map[string]interface{}{}
	if len(systemLogs) > 0 {
		logGroups = append(logGroups, map[string]interface{}{"system": systemLogs})
	}
	if len(securityLogs) > 0 {
		logGroups = append(logGroups, map[string]interface{}{"security": securityLogs})
	}
	if len(networkLogs) > 0 {
		logGroups = append(logGroups, map[string]interface{}{"network": networkLogs})
	}
	if len(policyLogs) > 0 {
		logGroups = append(logGroups, map[string]interface{}{"mdm": policyLogs})
	}
	if len(otherLogs) > 0 {
		logGroups = append(logGroups, map[string]interface{}{"other": otherLogs})
	}

	inner := map[string]interface{}{
		"agent_id":      u.cfg.DeviceID,
		"device_id":     u.cfg.DeviceID,
		"os_type":       runtime.GOOS,
		"agent_version": u.cfg.CurrentVersion,
		"source":        "agent",
		"logs":          logGroups,
	}

	return map[string]interface{}{
		"payload": inner,
	}
}

// UploadFromStore reads pending logs from the local SQLite queue, uploads them to
// Supabase in batches, and deletes each batch from the store on success.
// Rows that fail to upload are left in the store and retried on the next cycle.
// Returns the total number of logs successfully uploaded.
func (u *Uploader) UploadFromStore(ctx context.Context, auditStore *store.AuditLogStore) (int, error) {
	const chunkSize = 500

	if u.auth != nil && !u.auth.Healthy() {
		log.Printf("[uploader] auth degraded, deferring store upload until session recovers")
		return 0, nil
	}

	totalUploaded := 0
	var lastErr error

	for {
		if err := ctx.Err(); err != nil {
			return totalUploaded, err
		}

		rows, err := auditStore.GetPending(chunkSize)
		if err != nil {
			return totalUploaded, fmt.Errorf("get pending logs: %w", err)
		}
		if len(rows) == 0 {
			break
		}

		logs := make([]models.AuditLog, len(rows))
		ids := make([]int64, len(rows))
		for i, r := range rows {
			logs[i] = r.Log
			ids[i] = r.ID
		}

		if err := u.safeUploadBatch(ctx, logs); err != nil {
			lastErr = err
			u.stats.addErrors(int64(len(logs)))
			log.Printf("[uploader] store batch upload failed (%d logs): %v", len(logs), err)
			// Leave rows in DB; they will be retried next cycle.
			break
		}

		// These rows were uploaded successfully; count them regardless of the
		// delete outcome.
		totalUploaded += len(logs)
		u.stats.addUploaded(int64(len(logs)))

		if err := auditStore.DeleteByIDs(ids); err != nil {
			// CRITICAL: do NOT continue the loop on delete failure. The same rows
			// are still pending, so the next GetPending would return them again and
			// we would re-upload the identical batch in a tight loop for as long as
			// the DB error persists. Stop the cycle; the next scheduled cycle retries.
			lastErr = fmt.Errorf("delete uploaded logs from store: %w", err)
			log.Printf("[uploader] %v — stopping cycle to avoid re-uploading the same rows", lastErr)
			break
		}

		log.Printf("[uploader] uploaded and removed %d logs from store", len(logs))
	}

	return totalUploaded, lastErr
}
