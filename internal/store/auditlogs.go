package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

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

var auditLogMigrations = []Migration{
	{Version: 1, SQL: auditLogSchemaV1},
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
