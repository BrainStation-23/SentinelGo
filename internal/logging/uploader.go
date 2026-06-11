package logging

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	auditlogsvc "sentinelgo/internal/service/auditlog"
	"sentinelgo/internal/store"
)

const (
	maxBatchSize   = 100
	maxRetries     = 3
	initialBackoff = 1 * time.Second
)

// Uploader sends batches of audit logs to the Supabase backend
// via AuditLogService. It handles batch sizing and retry with
// exponential backoff.
type Uploader struct {
	svc   *auditlogsvc.AuditLogService
	cfg   *config.Config
	stats *statsCounter
}

// NewUploader creates an uploader wrapping the given audit log service.
func NewUploader(cfg *config.Config, stats *statsCounter) *Uploader {
	return &Uploader{
		svc:   auditlogsvc.NewAuditLogService(cfg),
		cfg:   cfg,
		stats: stats,
	}
}

// Upload sends the given logs in batches to the backend
// via the agent_insert_audit_logs_batch RPC function.
// Returns the total number of logs successfully uploaded.
func (u *Uploader) Upload(ctx context.Context, logs []models.AuditLog) (int, error) {
	if len(logs) == 0 {
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

		if err := u.uploadBatchWithRetry(ctx, batch); err != nil {
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

// uploadBatchWithRetry attempts to upload a single batch with exponential backoff.
func (u *Uploader) uploadBatchWithRetry(ctx context.Context, batch []models.AuditLog) error {
	batchData := u.buildBatchPayload(batch)

	backoff := initialBackoff
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = u.svc.SendBatchLogsWithContext(ctx, batchData)
		if lastErr == nil {
			return nil
		}

		if attempt < maxRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}

	return fmt.Errorf("upload failed after %d retries: %w", maxRetries, lastErr)
}

// buildBatchPayload constructs the map structure expected by SendBatchLogs.
func (u *Uploader) buildBatchPayload(logs []models.AuditLog) map[string]interface{} {
	// Group logs by category
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

	// Wrap in {"payload": {...}} as required by the RPC function
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

		if err := u.uploadBatchWithRetry(ctx, logs); err != nil {
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
