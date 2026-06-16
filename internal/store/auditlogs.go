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

// auditLogSchemaV2 adds a dead-letter table for rows the backend permanently rejects
// (a 4xx on enqueue). Quarantining the single offending row keeps it from dropping the
// rest of its upload batch, and keeps the rejected event inspectable instead of silently
// vanishing. The same retention prune applies so it cannot grow unbounded either.
const auditLogSchemaV2 = `
CREATE TABLE IF NOT EXISTS audit_log_deadletter (
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
    reason        TEXT    NOT NULL,
    dropped_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_deadletter_dropped ON audit_log_deadletter(dropped_at);
`

var auditLogMigrations = []Migration{
	{Version: 1, SQL: auditLogSchemaV1},
	{Version: 2, SQL: auditLogSchemaV2},
}

// AuditLogStore is a SQLite-backed queue for pending audit logs.
// Logs are inserted by the collector and deleted after successful upload to Supabase.
type AuditLogStore struct {
	db *sql.DB
}

// PendingRow pairs a DB row ID with the reconstructed AuditLog.
type PendingRow struct {
	ID  int64
	Log models.AuditLog
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

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO audit_log_queue
			(log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		); err != nil {
			return fmt.Errorf("insert log row: %w", err)
		}
	}

	return tx.Commit()
}

// GetPending returns up to limit rows that have not yet been uploaded.
// Pass limit <= 0 to retrieve all pending rows.
func (s *AuditLogStore) GetPending(limit int) ([]PendingRow, error) {
	query := `SELECT id, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data
              FROM audit_log_queue ORDER BY stored_at ASC`
	args := []interface{}{}

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

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

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	// #nosec G202 - placeholders is safely generated from strings.Repeat with only "?" and "," characters
	query := "DELETE FROM audit_log_queue WHERE id IN (" + placeholders + ")"

	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("delete uploaded logs: %w", err)
	}

	return nil
}

// Count returns the number of rows currently in the pending queue.
func (s *AuditLogStore) Count() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log_queue`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending logs: %w", err)
	}
	return n, nil
}

// DeadLetterCount returns the number of rows currently quarantined in the dead-letter table.
func (s *AuditLogStore) DeadLetterCount() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log_deadletter`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count dead-letter logs: %w", err)
	}
	return n, nil
}

// PruneByAge deletes queued rows older than maxAge and returns the number removed.
// A non-positive maxAge disables age-based pruning (no-op). Pruning a not-yet-uploaded
// row loses that audit event, so callers should run this only after an upload attempt.
func (s *AuditLogStore) PruneByAge(maxAge time.Duration) (int64, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	// stored_at and datetime('now', …) are both fixed-width UTC strings, so the textual
	// comparison is chronologically correct. Use seconds to honour sub-day durations.
	modifier := fmt.Sprintf("-%d seconds", int64(maxAge.Seconds()))
	res, err := s.db.Exec(`DELETE FROM audit_log_queue WHERE stored_at < datetime('now', ?)`, modifier)
	if err != nil {
		return 0, fmt.Errorf("prune audit logs by age: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneToMaxRows keeps the newest max rows (by id, which is insertion order) and deletes
// the rest, returning the number removed. A non-positive max disables the cap (no-op),
// and it is a no-op when the queue is already at or under max.
func (s *AuditLogStore) PruneToMaxRows(max int) (int64, error) {
	if max <= 0 {
		return 0, nil
	}
	// The subquery returns the id of the max-th newest row; everything older is deleted.
	// With fewer than max rows it yields NULL, so `id < NULL` matches nothing.
	res, err := s.db.Exec(`
		DELETE FROM audit_log_queue
		WHERE id < (SELECT id FROM audit_log_queue ORDER BY id DESC LIMIT 1 OFFSET ?)`,
		max-1)
	if err != nil {
		return 0, fmt.Errorf("prune audit logs to max rows: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeadLetter records logs the backend permanently rejected into the dead-letter table.
// The caller is responsible for removing them from the pending queue (via DeleteByIDs).
func (s *AuditLogStore) DeadLetter(logs []models.AuditLog, reason string) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin dead-letter tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO audit_log_deadletter
			(log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare dead-letter insert: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("AuditLogStore: close dead-letter stmt: %v", err)
		}
	}()

	for i := range logs {
		edJSON, err := normalizeEventData(logs[i].EventData)
		if err != nil {
			continue
		}
		if _, err := stmt.Exec(
			auditLogHash(&logs[i]),
			logs[i].DeviceID,
			logs[i].OSType,
			logs[i].AgentVersion,
			logs[i].EventType,
			logs[i].LogCategory,
			logs[i].Source,
			logs[i].Severity,
			logs[i].Timestamp,
			edJSON,
			reason,
		); err != nil {
			return fmt.Errorf("insert dead-letter row: %w", err)
		}
	}

	return tx.Commit()
}

// PruneDeadLetterByAge deletes dead-lettered rows older than maxAge so the quarantine
// table cannot grow unbounded either. Returns the number removed; non-positive maxAge
// is a no-op.
func (s *AuditLogStore) PruneDeadLetterByAge(maxAge time.Duration) (int64, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	modifier := fmt.Sprintf("-%d seconds", int64(maxAge.Seconds()))
	res, err := s.db.Exec(`DELETE FROM audit_log_deadletter WHERE dropped_at < datetime('now', ?)`, modifier)
	if err != nil {
		return 0, fmt.Errorf("prune dead-letter by age: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Maintain reclaims disk space: it truncates the WAL sidecar and returns free pages to
// the OS. A legacy database created before auto_vacuum was enabled (auto_vacuum reported
// as 0/NONE) is converted with a one-time full VACUUM — which also reclaims the existing
// bloat; subsequent calls use the cheap incremental path. VACUUM takes an exclusive lock
// and cannot run in a transaction, so this must be called off the hot path (it relies on
// the store's single-connection pool — see Open).
func (s *AuditLogStore) Maintain() error {
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}

	var autoVacuum int
	if err := s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return fmt.Errorf("read auto_vacuum: %w", err)
	}

	if autoVacuum == 0 {
		// Legacy file: VACUUM rewrites it in incremental-vacuum mode (the pragma set in
		// the DSN takes effect on this rewrite) and reclaims accumulated free pages.
		if _, err := s.db.Exec(`VACUUM`); err != nil {
			return fmt.Errorf("vacuum: %w", err)
		}
		return nil
	}

	if _, err := s.db.Exec(`PRAGMA incremental_vacuum`); err != nil {
		return fmt.Errorf("incremental vacuum: %w", err)
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
