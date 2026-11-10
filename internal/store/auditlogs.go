package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

const auditLogSchemaV1 = `
CREATE TABLE IF NOT EXISTS audit_log_queue (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    log_hash      TEXT    NOT NULL,
    device_id     TEXT    NOT NULL,
    os_type       TEXT    NOT NULL,
    agent_version TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    log_category  TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    event_data    TEXT    NOT NULL,
    stored_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_hash  ON audit_log_queue(log_hash);
CREATE INDEX        IF NOT EXISTS idx_audit_log_stored ON audit_log_queue(stored_at);
`

// auditLogSchemaV2 (#436):
//   - batch_id: the upload chunk a queued row belongs to, fixed when the chunk
//     is first formed, so every resend (retries, restarts) carries the same id
//     and the server can recognise a batch it already accepted.
//   - audit_log_uploaded: hashes of rows uploaded in the last day. Rows leave
//     the queue once uploaded, so without it a later poll that returns the
//     same event (the real-time subscription already delivered it) queued and
//     sent it again.
const auditLogSchemaV2 = `
ALTER TABLE audit_log_queue ADD COLUMN batch_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_log_batch ON audit_log_queue(batch_id);

CREATE TABLE IF NOT EXISTS audit_log_uploaded (
    log_hash    TEXT    PRIMARY KEY,
    uploaded_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_uploaded_at ON audit_log_uploaded(uploaded_at);
`

var auditLogMigrations = []Migration{
	{Version: 1, SQL: auditLogSchemaV1},
	{Version: 2, SQL: auditLogSchemaV2},
}

// maxUploadedHashes bounds audit_log_uploaded besides its age limit.
const maxUploadedHashes = 500_000

// AuditLogStore is a SQLite-backed queue for pending audit logs.
// Logs are inserted by the collector and deleted after successful upload to Supabase.
type AuditLogStore struct {
	db *sql.DB
}

// PendingRow pairs a DB row ID with the reconstructed AuditLog.
type PendingRow struct {
	ID      int64
	Hash    string // the row's dedup hash, sent as its uid
	BatchID string // empty until the row is assigned to an upload chunk
	Log     models.AuditLog
}

// NewAuditLogStore opens (or creates) the SQLite database at path and runs schema migrations.
func NewAuditLogStore(path string) (*AuditLogStore, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log store: %w", err)
	}

	if err := Migrate(db, auditLogMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate audit log store: %w", err)
	}

	return &AuditLogStore{db: db}, nil
}

// Insert writes logs to the queue. Duplicates (same log_hash) are silently ignored.
func (s *AuditLogStore) Insert(logs []models.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin insert tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A row uploaded recently (see audit_log_uploaded) is not queued again.
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO audit_log_queue
			(log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM audit_log_uploaded WHERE log_hash = ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("AuditLogStore: close stmt: %v", err)
		}
	}()

	for i := range logs {
		edJSON, err := normalizeEventData(logs[i].EventData)
		if err != nil {
			continue
		}
		h := auditLogHash(&logs[i])
		if _, err := stmt.Exec(
			h,
			logs[i].DeviceID,
			logs[i].OSType,
			logs[i].AgentVersion,
			logs[i].EventType,
			logs[i].LogCategory,
			logs[i].Source,
			logs[i].Severity,
			logs[i].Timestamp,
			edJSON,
			h,
		); err != nil {
			return fmt.Errorf("insert log row: %w", err)
		}
	}

	return tx.Commit()
}

// GetPending returns up to limit rows that have not yet been uploaded.
// Pass limit <= 0 to retrieve all pending rows.
func (s *AuditLogStore) GetPending(limit int) ([]PendingRow, error) {
	if limit <= 0 {
		limit = -1 // SQLite: no limit
	}
	return s.queryPending(`SELECT id, log_hash, COALESCE(batch_id, ''), device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data
		FROM audit_log_queue ORDER BY stored_at ASC, id ASC LIMIT ?`, limit)
}

// GetOpenBatch returns the rows of the oldest upload chunk that was formed
// but not yet confirmed, or nil when there is none. They must be sent again
// with the same batch id (#436).
func (s *AuditLogStore) GetOpenBatch() ([]PendingRow, error) {
	return s.queryPending(`SELECT id, log_hash, COALESCE(batch_id, ''), device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data
		FROM audit_log_queue
		WHERE batch_id = (SELECT batch_id FROM audit_log_queue WHERE batch_id IS NOT NULL ORDER BY id LIMIT 1)
		ORDER BY id`)
}

// GetUnbatched returns up to limit queued rows that belong to no upload
// chunk yet, oldest first.
func (s *AuditLogStore) GetUnbatched(limit int) ([]PendingRow, error) {
	return s.queryPending(`SELECT id, log_hash, COALESCE(batch_id, ''), device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data
		FROM audit_log_queue WHERE batch_id IS NULL ORDER BY stored_at ASC, id ASC LIMIT ?`, limit)
}

// AssignBatch puts the rows with the given IDs into upload chunk batchID.
func (s *AuditLogStore) AssignBatch(ids []int64, batchID string) error {
	if len(ids) == 0 {
		return nil
	}
	query, args := idsQuery("UPDATE audit_log_queue SET batch_id = ? WHERE id IN (", ids, batchID)
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("assign upload batch: %w", err)
	}
	return nil
}

// CompleteBatch removes uploaded rows from the queue and remembers their
// hashes in audit_log_uploaded, in one transaction, so the same events
// collected again are not queued again.
func (s *AuditLogStore) CompleteBatch(rows []PendingRow, now time.Time) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin complete tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO audit_log_uploaded (log_hash, uploaded_at) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare uploaded insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
		if _, err := stmt.Exec(r.Hash, now.Unix()); err != nil {
			return fmt.Errorf("record uploaded hash: %w", err)
		}
	}
	query, args := idsQuery("DELETE FROM audit_log_queue WHERE id IN (", ids)
	if _, err := tx.Exec(query, args...); err != nil {
		return fmt.Errorf("delete uploaded logs: %w", err)
	}
	return tx.Commit()
}

// PruneUploaded forgets uploaded hashes older than before, and the oldest
// ones beyond maxUploadedHashes.
func (s *AuditLogStore) PruneUploaded(before time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM audit_log_uploaded WHERE uploaded_at < ?`, before.Unix()); err != nil {
		return fmt.Errorf("prune uploaded hashes: %w", err)
	}
	if _, err := s.db.Exec(`DELETE FROM audit_log_uploaded WHERE log_hash IN (
		SELECT log_hash FROM audit_log_uploaded ORDER BY uploaded_at DESC LIMIT -1 OFFSET ?)`, maxUploadedHashes); err != nil {
		return fmt.Errorf("cap uploaded hashes: %w", err)
	}
	return nil
}

// idsQuery appends one placeholder per id and the closing parenthesis to
// prefix (a constant statement); lead are bound before the ids.
func idsQuery(prefix string, ids []int64, lead ...any) (string, []any) {
	placeholders := strings.Repeat("?,", len(ids))
	args := make([]any, 0, len(lead)+len(ids))
	args = append(args, lead...)
	for _, id := range ids {
		args = append(args, id)
	}
	// #nosec G202 - only "?" and "," are appended to a constant statement
	return prefix + placeholders[:len(placeholders)-1] + ")", args
}

func (s *AuditLogStore) queryPending(query string, args ...any) ([]PendingRow, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query pending logs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("AuditLogStore: close rows: %v", err)
		}
	}()

	var result []PendingRow
	for rows.Next() {
		var pr PendingRow
		var eventDataStr string

		if err := rows.Scan(
			&pr.ID,
			&pr.Hash,
			&pr.BatchID,
			&pr.Log.DeviceID,
			&pr.Log.OSType,
			&pr.Log.AgentVersion,
			&pr.Log.EventType,
			&pr.Log.LogCategory,
			&pr.Log.Source,
			&pr.Log.Severity,
			&pr.Log.Timestamp,
			&eventDataStr,
		); err != nil {
			return nil, fmt.Errorf("scan pending row: %w", err)
		}

		pr.Log.AgentID = pr.Log.DeviceID
		pr.Log.EventData = json.RawMessage(eventDataStr)
		result = append(result, pr)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending rows: %w", err)
	}

	return result, nil
}

// DeleteByIDs removes rows with the given IDs from the queue after a successful upload.
func (s *AuditLogStore) DeleteByIDs(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	query, args := idsQuery("DELETE FROM audit_log_queue WHERE id IN (", ids)
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("delete uploaded logs: %w", err)
	}

	return nil
}

// Close closes the underlying database connection.
func (s *AuditLogStore) Close() error {
	return s.db.Close()
}

// auditLogHash produces a stable dedup key from the log's identifying fields.
// Matches the algorithm used in internal/logging/buffer.go.
func auditLogHash(l *models.AuditLog) string {
	h := sha256.New()
	h.Write([]byte(l.Source))
	h.Write([]byte{0})
	h.Write([]byte(l.Timestamp))
	h.Write([]byte{0})
	h.Write([]byte(l.EventType))
	h.Write([]byte{0})
	h.Write(l.EventData)
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeEventData ensures event_data is stored as a valid JSON string.
func normalizeEventData(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}
	if !json.Valid(raw) {
		return "", fmt.Errorf("invalid JSON in event_data")
	}
	return string(raw), nil
}
