package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	auditlogsvc "sentinelgo/internal/service/auditlog"
	"sentinelgo/internal/service/rpcutil"
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
// Supabase in batches of at most maxBatchSize, and deletes each batch from the store
// once it is resolved. A row the backend permanently rejects (4xx) is isolated by
// bisection and moved to the dead-letter table so it cannot drop the rest of its batch.
// Rows that fail with a transient error are left in the store and retried next cycle.
// Returns the total number of logs successfully uploaded (dead-lettered rows excluded).
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

		uploaded, stop, chunkErr := u.uploadChunk(ctx, auditStore, rows)
		totalUploaded += uploaded
		if chunkErr != nil {
			lastErr = chunkErr
		}
		if stop {
			break
		}
	}

	return totalUploaded, lastErr
}

// uploadChunk sends one GetPending chunk in batches of at most maxBatchSize, deleting the
// resolved rows of each batch as it goes. It returns the number of rows uploaded, whether
// the cycle should stop (a transient upload error or a delete failure leaves rows queued
// for the next cycle), and the error to surface.
func (u *Uploader) uploadChunk(ctx context.Context, auditStore *store.AuditLogStore, rows []store.PendingRow) (uploaded int, stop bool, err error) {
	for start := 0; start < len(rows); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(rows) {
			end = len(rows)
		}

		n, resolved, upErr := u.uploadOrIsolate(ctx, auditStore, rows[start:end])
		uploaded += n

		// Remove resolved rows (uploaded or dead-lettered) first so a partial failure
		// does not re-process what already succeeded.
		if len(resolved) > 0 {
			if delErr := auditStore.DeleteByIDs(resolved); delErr != nil {
				// Do NOT continue on delete failure: the same rows are still pending and
				// would be re-processed in a tight loop. Stop; the next cycle retries.
				delErr = fmt.Errorf("delete resolved logs from store: %w", delErr)
				log.Printf("[uploader] %v — stopping cycle to avoid re-processing the same rows", delErr)
				return uploaded, true, delErr
			}
		}

		if upErr != nil {
			// Transient (5xx/network/ctx): leave the remaining rows queued.
			log.Printf("[uploader] store batch upload failed: %v", upErr)
			return uploaded, true, upErr
		}
	}
	return uploaded, false, nil
}

// uploadOrIsolate uploads a batch of pending rows. It returns the number of rows that
// uploaded successfully, the IDs of all rows that are now resolved (uploaded OR moved to
// the dead-letter table) and should be removed from the pending queue, and a non-nil
// error only for transient failures (the rows should stay queued for the next cycle).
//
// On a backend rejection (*rpcutil.RejectedError) the batch is bisected to isolate the
// offending row(s): a single rejected row is dead-lettered, larger batches are split and
// retried so good rows are not lost alongside it.
func (u *Uploader) uploadOrIsolate(ctx context.Context, auditStore *store.AuditLogStore, rows []store.PendingRow) (uploaded int, resolved []int64, err error) {
	if len(rows) == 0 {
		return 0, nil, nil
	}

	logs := make([]models.AuditLog, len(rows))
	for i, r := range rows {
		logs[i] = r.Log
	}

	uploadErr := u.safeUploadBatch(ctx, logs)
	if uploadErr == nil {
		ids := make([]int64, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		u.stats.addUploaded(int64(len(rows)))
		return len(rows), ids, nil
	}

	var rej *rpcutil.RejectedError
	if !errors.As(uploadErr, &rej) {
		// Transient error: leave these rows queued and surface it to the caller.
		u.stats.addErrors(int64(len(rows)))
		return 0, nil, uploadErr
	}

	// A single rejected row is the poison — quarantine it so it stops blocking the queue.
	if len(rows) == 1 {
		log.Printf("[uploader] dead-lettering rejected audit log (HTTP %d): %v", rej.Status, rej.Err)
		if dlErr := auditStore.DeadLetter(logs, rej.Error()); dlErr != nil {
			// Could not quarantine it; leave it queued rather than silently lose it.
			u.stats.addErrors(1)
			return 0, nil, fmt.Errorf("dead-letter rejected log: %w", dlErr)
		}
		u.stats.addErrors(1)
		return 0, []int64{rows[0].ID}, nil
	}

	// Bisect to isolate the offending row(s) within each half.
	mid := len(rows) / 2
	leftUp, leftIDs, leftErr := u.uploadOrIsolate(ctx, auditStore, rows[:mid])
	if leftErr != nil {
		return leftUp, leftIDs, leftErr
	}
	rightUp, rightIDs, rightErr := u.uploadOrIsolate(ctx, auditStore, rows[mid:])
	return leftUp + rightUp, append(leftIDs, rightIDs...), rightErr
}
