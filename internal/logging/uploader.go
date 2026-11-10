package logging

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"sort"
	"time"

	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	auditlogsvc "sentinelgo/internal/service/auditlog"
	"sentinelgo/internal/store"
)

const (
	maxBatchSize = 100
	// maxPayloadBytes caps one upload body. Smaller batches retry faster and
	// keep the server's per-message cost flat (#438); the enqueue limit is 1 MB.
	maxPayloadBytes = 256 << 10
	// storeChunkSize is how many queued rows one store upload considers.
	storeChunkSize = 500
	// uploadedMemory is how long uploaded rows' hashes are remembered, so the
	// same event collected again is not queued again (#436).
	uploadedMemory = 24 * time.Hour
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
	svc    *auditlogsvc.AuditLogService
	cfg    *config.Config
	stats  *statsCounter
	auth   authRetrier  // optional; when set, uploads recover the session on 401
	window *auditWindow // optional; receives the server's window from each response
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

	for i := 0; i < len(logs); {
		end := min(i+maxBatchSize, len(logs))
		batch := logs[i:end]
		batch = batch[:u.fitCount(batch, nil)]
		i += len(batch)

		if _, err := u.send(ctx, batch, nil, newBatchID()); err != nil {
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

// fitCount returns how many of logs, from the start, fit in one upload body of
// at most maxPayloadBytes (at least 1, so a single oversized row still goes).
func (u *Uploader) fitCount(logs []models.AuditLog, uids []string) int {
	fits := func(n int) bool {
		var ids []string
		if uids != nil {
			ids = uids[:n]
		}
		data, err := json.Marshal(u.buildPayload(logs[:n], ids, "00000000-0000-4000-8000-000000000000"))
		return err == nil && len(data) <= maxPayloadBytes
	}
	if len(logs) == 0 || fits(len(logs)) {
		return len(logs)
	}
	// The largest n in [1, len) that fits; n = 1 is sent even when it doesn't.
	n := sort.Search(len(logs), func(n int) bool { return n > 0 && !fits(n) }) - 1
	return max(n, 1)
}

// send uploads one batch under batchID and passes the server's window on.
// Retry is handled inside SendBatch via WithEnqueueRetry, with the same body
// (and so the same batch_id) every time; DoWithAuthRetry wraps it for 401
// recovery.
func (u *Uploader) send(ctx context.Context, logs []models.AuditLog, uids []string, batchID string) (auditlogsvc.BatchResult, error) {
	batchData := u.buildPayload(logs, uids, batchID)

	var res auditlogsvc.BatchResult
	call := func() error {
		var err error
		res, err = u.svc.SendBatch(ctx, batchData)
		return err
	}
	var err error
	if u.auth != nil {
		err = u.auth.DoWithAuthRetry(ctx, u.cfg, call)
	} else {
		err = call()
	}
	if err != nil {
		return res, err
	}
	if res.Duplicate {
		log.Printf("[uploader] server already had batch %s (%d logs); treating it as uploaded", batchID, len(logs))
	}
	u.window.update(res.Window)
	return res, nil
}

// newBatchID returns a random (version 4) UUID.
func newBatchID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// buildPayload constructs the map structure expected by SendBatch. batchID
// (when set) lets the server recognise a resend of a batch it already has;
// uids[i] (when set) is logs[i]'s dedup key (#436). event_data is trimmed to
// the server's limit, for rows queued before the parser did that (#438).
func (u *Uploader) buildPayload(logs []models.AuditLog, uids []string, batchID string) map[string]interface{} {
	target := u.window.eventDataTarget()
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
			"event_data":   parser.CapEventData(logs[i].EventData, target),
		}
		if i < len(uids) && uids[i] != "" {
			entry["uid"] = uids[i]
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
	if batchID != "" {
		inner["batch_id"] = batchID
	}

	return map[string]interface{}{
		"payload": inner,
	}
}

// UploadFromStore uploads the local SQLite queue to Supabase, one chunk at a
// time, and removes each chunk from the queue once the server has it.
//
// Each chunk gets a batch_id when it is formed (at most storeChunkSize rows
// and maxPayloadBytes of body) and keeps it until it is confirmed, across
// retries and restarts, so the server can recognise a resend (#436). A chunk
// that fails stays queued with its id and is sent first next cycle; nothing
// that was confirmed is ever resent. Returns the number of logs uploaded.
func (u *Uploader) UploadFromStore(ctx context.Context, auditStore *store.AuditLogStore) (int, error) {
	if u.auth != nil && !u.auth.Healthy() {
		log.Printf("[uploader] auth degraded, deferring store upload until session recovers")
		return 0, nil
	}

	if err := auditStore.PruneUploaded(time.Now().Add(-uploadedMemory)); err != nil {
		log.Printf("[uploader] warning: %v", err)
	}

	totalUploaded := 0
	var lastErr error

	for {
		if err := ctx.Err(); err != nil {
			return totalUploaded, err
		}

		rows, err := u.nextChunk(auditStore)
		if err != nil {
			return totalUploaded, err
		}
		if len(rows) == 0 {
			break
		}

		logs := make([]models.AuditLog, len(rows))
		uids := make([]string, len(rows))
		for i, r := range rows {
			logs[i] = r.Log
			uids[i] = r.Hash
		}

		if _, err := u.send(ctx, logs, uids, rows[0].BatchID); err != nil {
			lastErr = err
			u.stats.addErrors(int64(len(logs)))
			log.Printf("[uploader] store batch upload failed (%d logs): %v", len(logs), err)
			// Leave the chunk queued with its batch id; it is resent next cycle.
			break
		}

		// These rows were uploaded successfully; count them regardless of the
		// delete outcome.
		totalUploaded += len(logs)
		u.stats.addUploaded(int64(len(logs)))

		if err := auditStore.CompleteBatch(rows, time.Now()); err != nil {
			// CRITICAL: do NOT continue the loop on delete failure. The same rows
			// are still pending, so the next chunk would be the identical batch,
			// re-uploaded in a tight loop for as long as the DB error persists.
			// Stop the cycle; the next scheduled cycle retries (with the same
			// batch id, so the server drops the repeat).
			lastErr = fmt.Errorf("delete uploaded logs from store: %w", err)
			log.Printf("[uploader] %v — stopping cycle to avoid re-uploading the same rows", lastErr)
			break
		}

		log.Printf("[uploader] uploaded and removed %d logs from store", len(logs))
	}

	return totalUploaded, lastErr
}

// nextChunk returns the chunk to upload next: one formed earlier and not yet
// confirmed, else a new one from the oldest unassigned rows, sized to fit one
// upload body and given a new batch id.
func (u *Uploader) nextChunk(auditStore *store.AuditLogStore) ([]store.PendingRow, error) {
	rows, err := auditStore.GetOpenBatch()
	if err != nil {
		return nil, fmt.Errorf("get open batch: %w", err)
	}
	if len(rows) > 0 {
		return rows, nil
	}

	rows, err = auditStore.GetUnbatched(storeChunkSize)
	if err != nil {
		return nil, fmt.Errorf("get pending logs: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	logs := make([]models.AuditLog, len(rows))
	uids := make([]string, len(rows))
	for i, r := range rows {
		logs[i], uids[i] = r.Log, r.Hash
	}
	rows = rows[:u.fitCount(logs, uids)]

	id := newBatchID()
	ids := make([]int64, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
		rows[i].BatchID = id
	}
	if err := auditStore.AssignBatch(ids, id); err != nil {
		return nil, err
	}
	return rows, nil
}
