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

// auditLogSchemaV2 adds durable eviction counters.
//
// The queue was previously unbounded: rows were deleted only on successful
// upload, so an agent whose backend was unreachable — or whose payloads the
// backend permanently rejected — grew this table until the endpoint's disk
// filled. Bounding it means deliberately discarding audit records, and an audit
// trail that silently loses entries is worse than one that admits to it. These
// counters are what make the loss visible and quantified: they persist across
// restarts, so an operator can see that a device dropped events and how many,
// long after the log line scrolled away.
const auditLogSchemaV2 = `
CREATE TABLE IF NOT EXISTS audit_log_evictions (
    reason        TEXT    PRIMARY KEY,
    dropped       INTEGER NOT NULL DEFAULT 0,
    last_at       TEXT    NOT NULL DEFAULT '',
    last_severity TEXT    NOT NULL DEFAULT ''
);
`

var auditLogMigrations = []Migration{
	{Version: 1, SQL: auditLogSchemaV1},
	{Version: 2, SQL: auditLogSchemaV2},
}

// Eviction reasons. Stored as the primary key of audit_log_evictions, so these
// strings are persisted data — add to them, never rename one.
const (
	EvictReasonAge   = "age"
	EvictReasonRows  = "rows"
	EvictReasonBytes = "bytes"
)

// AuditLogLimits bounds the audit queue along the three axes that can each run
// away independently.
//
// These mirror the telemetry outbound queue's limits deliberately: the same
// failure (a backend that is unreachable, or is rejecting everything) drives
// both, and two different answers to the same problem on one endpoint would be
// a maintenance trap. Zero on a field disables that axis.
type AuditLogLimits struct {
	MaxAge   time.Duration
	MaxRows  int
	MaxBytes int64
}

// DefaultAuditLogLimits are the shipped defaults.
//
// The age and byte bounds match the telemetry queue (72h, 64 MiB). The row cap
// does not: audit rows are individual OS event-log records, not batched
// telemetry messages, and a Windows Security log alone can produce thousands of
// events per hour. 5,000 rows — the telemetry figure — would evict a normally
// functioning endpoint's backlog during any ordinary upload delay, so the cap
// sits an order of magnitude higher, where it bounds a runaway without touching
// healthy operation.
func DefaultAuditLogLimits() AuditLogLimits {
	return AuditLogLimits{
		MaxAge:   72 * time.Hour,
		MaxRows:  50000,
		MaxBytes: 64 * 1024 * 1024,
	}
}

// auditRowBytesSQL is the on-disk size of one queued row, as a SQL expression.
//
// Computed from the text columns rather than stored in a byte_size column: an
// ALTER TABLE adding such a column would default every pre-existing row to 0,
// so an agent upgrading with a large backlog would believe its queue was empty
// and enforce no byte bound at all over exactly the rows that made the bound
// necessary. Summing lengths is always correct, including immediately after the
// upgrade.
const auditRowBytesSQL = `(length(event_data) + length(log_hash) + length(device_id) +
	length(os_type) + length(agent_version) + length(event_type) +
	length(log_category) + length(source) + length(severity) + length(timestamp))`

// auditSeverityRankSQL ranks a row for eviction, as a SQL expression.
//
// Severity is stored as a syslog numeric string where LOWER is more severe
// ("0" emergency … "7" debug), so a plain descending sort puts the least
// important records first. Values that are not a single digit — severities
// written by other code paths as words — rank as 6 ("informational") rather
// than CASTing to 0, which is what SQLite does for any non-numeric text and
// which would make every such row look like an emergency and permanently
// un-evictable.
const auditSeverityRankSQL = `(CASE WHEN severity GLOB '[0-9]' THEN CAST(severity AS INTEGER) ELSE 6 END)`

// AuditLogStore is a SQLite-backed queue for pending audit logs.
// Logs are inserted by the collector and deleted after successful upload to Supabase.
type AuditLogStore struct {
	db     *sql.DB
	limits AuditLogLimits
}

// PendingRow pairs a DB row ID with the reconstructed AuditLog.
type PendingRow struct {
	ID  int64
	Log models.AuditLog
}

// NewAuditLogStore opens (or creates) the SQLite database at path and runs
// schema migrations, applying DefaultAuditLogLimits.
func NewAuditLogStore(path string) (*AuditLogStore, error) {
	return NewAuditLogStoreWithLimits(path, DefaultAuditLogLimits())
}

// NewAuditLogStoreWithLimits is NewAuditLogStore with explicit retention bounds.
//
// Every axis defaults INDEPENDENTLY: a zero or negative field takes the shipped
// default rather than meaning "unbounded". Unbounded is exactly the behaviour
// this store is being fixed to remove, so no combination of config values may
// reach it — including a config file written before these keys existed, which
// deserialises to a zero struct. Per-axis rather than all-or-nothing so an
// operator can raise one bound without silently unbounding the other two.
func NewAuditLogStoreWithLimits(path string, limits AuditLogLimits) (*AuditLogStore, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log store: %w", err)
	}

	if err := Migrate(db, auditLogMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate audit log store: %w", err)
	}

	return &AuditLogStore{db: db, limits: limits.withDefaults()}, nil
}

// withDefaults fills in each unset axis from DefaultAuditLogLimits.
func (l AuditLogLimits) withDefaults() AuditLogLimits {
	d := DefaultAuditLogLimits()
	if l.MaxAge <= 0 {
		l.MaxAge = d.MaxAge
	}
	if l.MaxRows <= 0 {
		l.MaxRows = d.MaxRows
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	return l
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

	if err := tx.Commit(); err != nil {
		return err
	}

	// Enforce retention after the rows are durable, never inside the insert
	// transaction. Pruning is best-effort maintenance: a failure to evict must
	// not fail the collection that just succeeded, or a full disk would also
	// cost the agent the events it had already parsed.
	if res, pruneErr := s.Prune(); pruneErr != nil {
		log.Printf("AuditLogStore: prune after insert: %v", pruneErr)
	} else if res.Total() > 0 {
		log.Printf("[auditlog] queue over retention bounds: evicted %d row(s) "+
			"(age=%d rows=%d bytes=%d); uploads are not keeping up with collection",
			res.Total(), res.ByAge, res.ByRows, res.ByBytes)
	}

	return nil
}

// EvictionResult reports what one Prune pass removed, by which bound.
type EvictionResult struct {
	ByAge   int64
	ByRows  int64
	ByBytes int64
}

// Total is the number of rows the pass evicted.
func (r EvictionResult) Total() int64 { return r.ByAge + r.ByRows + r.ByBytes }

// Prune enforces the retention bounds and returns what it removed.
//
// Eviction order within the row and byte bounds is least-severe-first, then
// oldest-first, so a flood of routine "information" events can never push out
// an unsent critical record queued behind it. The age bound is deliberately
// different and is unconditional: a three-day-old event is no longer
// actionable regardless of severity, and exempting critical rows from it would
// let a permanently-rejecting backend accumulate them without limit — which is
// the disk-fill this bound exists to stop.
func (s *AuditLogStore) Prune() (EvictionResult, error) {
	var res EvictionResult

	if s.limits.MaxAge > 0 {
		n, err := s.pruneByAge()
		if err != nil {
			return res, fmt.Errorf("prune by age: %w", err)
		}
		res.ByAge = n
	}

	if s.limits.MaxRows > 0 {
		n, err := s.pruneByRows()
		if err != nil {
			return res, fmt.Errorf("prune by rows: %w", err)
		}
		res.ByRows = n
	}

	if s.limits.MaxBytes > 0 {
		n, err := s.pruneByBytes()
		if err != nil {
			return res, fmt.Errorf("prune by bytes: %w", err)
		}
		res.ByBytes = n
	}

	return res, nil
}

// pruneByAge removes rows older than MaxAge.
//
// stored_at is written by SQLite's CURRENT_TIMESTAMP, whose format is
// "YYYY-MM-DD HH:MM:SS" in UTC. The cutoff is formatted to match so the
// comparison is a plain lexicographic string compare, which for this format is
// also a chronological one.
func (s *AuditLogStore) pruneByAge() (int64, error) {
	cutoff := time.Now().UTC().Add(-s.limits.MaxAge).Format("2006-01-02 15:04:05")
	return s.evict(EvictReasonAge,
		"DELETE FROM audit_log_queue WHERE id IN (SELECT id FROM audit_log_queue WHERE stored_at < ?)",
		cutoff)
}

// pruneByRows evicts until the row count fits MaxRows.
func (s *AuditLogStore) pruneByRows() (int64, error) {
	var count int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log_queue").Scan(&count); err != nil {
		return 0, err
	}
	excess := count - int64(s.limits.MaxRows)
	if excess <= 0 {
		return 0, nil
	}
	return s.evictLeastImportant(EvictReasonRows, excess)
}

// pruneByBytes evicts until the total row size fits MaxBytes.
//
// It evicts in batches proportional to the overage rather than one row at a
// time: a queue 40 MiB over its bound does not need forty thousand separate
// DELETE statements to converge.
func (s *AuditLogStore) pruneByBytes() (int64, error) {
	var total int64
	for {
		var sum sql.NullInt64
		if err := s.db.QueryRow("SELECT SUM" + auditRowBytesSQL + " FROM audit_log_queue").Scan(&sum); err != nil {
			return total, err
		}
		if !sum.Valid || sum.Int64 <= s.limits.MaxBytes {
			return total, nil
		}

		var rows int64
		if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log_queue").Scan(&rows); err != nil {
			return total, err
		}
		if rows == 0 {
			return total, nil
		}

		// Estimate how many average-sized rows cover the overage, and always
		// remove at least one so this cannot spin without making progress.
		batch := int64(1)
		if avg := sum.Int64 / rows; avg > 0 {
			if want := (sum.Int64 - s.limits.MaxBytes + avg - 1) / avg; want > batch {
				batch = want
			}
		}

		n, err := s.evictLeastImportant(EvictReasonBytes, batch)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
	}
}

// evictLeastImportant deletes up to n rows, least severe and oldest first.
func (s *AuditLogStore) evictLeastImportant(reason string, n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	return s.evict(reason, `
		DELETE FROM audit_log_queue WHERE id IN (
			SELECT id FROM audit_log_queue
			ORDER BY `+auditSeverityRankSQL+` DESC, stored_at ASC, id ASC
			LIMIT ?
		)`, n)
}

// evict runs a deletion and records what it removed.
//
// The severity of the most important row about to be discarded is captured
// BEFORE the delete, because afterwards the evidence is gone. That single field
// is what tells an operator whether a device shed routine informational noise or
// genuine security events.
func (s *AuditLogStore) evict(reason, query string, args ...interface{}) (int64, error) {
	worst := s.mostSevereMatching(query, args...)

	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		// The delete itself succeeded; only the count is unavailable.
		return 0, nil
	}

	s.recordEviction(reason, affected, worst)
	return affected, nil
}

// mostSevereMatching reports the severity of the most important row a pending
// deletion would remove. Best-effort: it is diagnostic metadata, so a failure
// here must not stop the eviction that keeps the disk from filling.
func (s *AuditLogStore) mostSevereMatching(deleteQuery string, args ...interface{}) string {
	selectQuery := strings.Replace(deleteQuery,
		"DELETE FROM audit_log_queue WHERE id IN (",
		"SELECT MIN"+auditSeverityRankSQL+" FROM audit_log_queue WHERE id IN (", 1)
	if selectQuery == deleteQuery {
		return ""
	}

	var sev sql.NullInt64
	if err := s.db.QueryRow(selectQuery, args...).Scan(&sev); err != nil || !sev.Valid {
		return ""
	}
	return fmt.Sprintf("%d", sev.Int64)
}

// recordEviction accumulates the durable drop counters.
func (s *AuditLogStore) recordEviction(reason string, n int64, worstSeverity string) {
	_, err := s.db.Exec(`
		INSERT INTO audit_log_evictions (reason, dropped, last_at, last_severity)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(reason) DO UPDATE SET
			dropped = dropped + excluded.dropped,
			last_at = excluded.last_at,
			last_severity = excluded.last_severity`,
		reason, n, time.Now().UTC().Format(time.RFC3339), worstSeverity)
	if err != nil {
		log.Printf("AuditLogStore: record eviction counter (%s, %d rows): %v", reason, n, err)
	}
}

// EvictionCounter is the durable record of what one bound has discarded.
type EvictionCounter struct {
	Reason string
	// Dropped is cumulative across the lifetime of the database file, not
	// per-run: the point is that an operator can see a device has been losing
	// audit records for days, not just since the last restart.
	Dropped int64
	LastAt  string
	// LastSeverity is the syslog rank of the most severe record removed by the
	// most recent eviction for this reason. "2" or lower means genuine security
	// events are being discarded, not routine noise.
	LastSeverity string
}

// EvictionStats returns the durable drop counters, one per reason that has
// evicted anything.
func (s *AuditLogStore) EvictionStats() ([]EvictionCounter, error) {
	rows, err := s.db.Query(
		"SELECT reason, dropped, last_at, last_severity FROM audit_log_evictions ORDER BY reason")
	if err != nil {
		return nil, fmt.Errorf("query eviction counters: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Printf("AuditLogStore: close eviction rows: %v", closeErr)
		}
	}()

	var out []EvictionCounter
	for rows.Next() {
		var c EvictionCounter
		if err := rows.Scan(&c.Reason, &c.Dropped, &c.LastAt, &c.LastSeverity); err != nil {
			return nil, fmt.Errorf("scan eviction counter: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TotalDropped is the total number of audit records this store has ever
// discarded to stay inside its bounds.
func (s *AuditLogStore) TotalDropped() (int64, error) {
	var n sql.NullInt64
	if err := s.db.QueryRow("SELECT SUM(dropped) FROM audit_log_evictions").Scan(&n); err != nil {
		return 0, fmt.Errorf("sum dropped: %w", err)
	}
	if !n.Valid {
		return 0, nil
	}
	return n.Int64, nil
}

// Depth is the number of rows currently queued for upload.
func (s *AuditLogStore) Depth() (int, error) {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log_queue").Scan(&n); err != nil {
		return 0, fmt.Errorf("count queued logs: %w", err)
	}
	return n, nil
}

// TotalBytes is the current on-disk size of the queued rows, by the same
// measure the byte bound enforces.
func (s *AuditLogStore) TotalBytes() (int64, error) {
	var sum sql.NullInt64
	if err := s.db.QueryRow("SELECT SUM" + auditRowBytesSQL + " FROM audit_log_queue").Scan(&sum); err != nil {
		return 0, fmt.Errorf("sum queued bytes: %w", err)
	}
	if !sum.Valid {
		return 0, nil
	}
	return sum.Int64, nil
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
