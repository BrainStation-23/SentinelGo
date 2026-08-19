package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// TelemetryOutboundDBName is the filename of the telemetry send queue, placed
// alongside config.json like the other agent stores.
const TelemetryOutboundDBName = "sentinelgo_telemetry_queue.db"

// telemetryOutboundSchemaV1 is the durable send queue for telemetry messages.
//
// Payloads live here only while in flight and are deleted on successful
// delivery. Unlike the section-state table, this one must hold the body so an
// agent that is offline for hours does not lose what it collected.
const telemetryOutboundSchemaV1 = `
CREATE TABLE IF NOT EXISTS telemetry_outbound (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id TEXT    NOT NULL,
	section     TEXT    NOT NULL,
	class       TEXT    NOT NULL,
	priority    INTEGER NOT NULL DEFAULT 50,
	batch_index INTEGER NOT NULL DEFAULT 0,
	batch_count INTEGER NOT NULL DEFAULT 1,
	payload     TEXT    NOT NULL,
	byte_size   INTEGER NOT NULL DEFAULT 0,
	attempts    INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tel_outbound_priority ON telemetry_outbound(priority, id);
CREATE INDEX IF NOT EXISTS idx_tel_outbound_created  ON telemetry_outbound(created_at);
`

var telemetryOutboundMigrations = []Migration{
	{Version: 1, SQL: telemetryOutboundSchemaV1},
}

// OutboundLimits bounds the queue so a long-offline agent cannot fill its disk.
//
// The existing audit-log queue has no such bound; this one is capped from the
// start along all three axes that can independently run away: age, row count
// and total bytes.
type OutboundLimits struct {
	MaxAge   time.Duration
	MaxRows  int
	MaxBytes int64
}

// DefaultOutboundLimits are the shipped defaults, overridable from config.
func DefaultOutboundLimits() OutboundLimits {
	return OutboundLimits{
		MaxAge:   72 * time.Hour,
		MaxRows:  5000,
		MaxBytes: 64 * 1024 * 1024,
	}
}

// OutboundMessage is one queued telemetry message.
type OutboundMessage struct {
	ID         int64
	SnapshotID string
	Section    string
	Class      string
	Priority   int
	BatchIndex int
	BatchCount int
	Payload    string
	ByteSize   int
	Attempts   int
	CreatedAt  time.Time
}

// TelemetryOutboundStore is the bounded durable send queue.
type TelemetryOutboundStore struct {
	db     *sql.DB
	limits OutboundLimits
}

// NewTelemetryOutboundStore opens (or creates) the queue at dbPath.
func NewTelemetryOutboundStore(dbPath string, limits OutboundLimits) (*TelemetryOutboundStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open telemetry outbound store: %w", err)
	}
	if err := Migrate(db, telemetryOutboundMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate telemetry outbound store: %w", err)
	}
	if limits.MaxAge <= 0 && limits.MaxRows <= 0 && limits.MaxBytes <= 0 {
		limits = DefaultOutboundLimits()
	}
	return &TelemetryOutboundStore{db: db, limits: limits}, nil
}

// Enqueue appends a message and then enforces the retention bounds.
// It returns how many messages were evicted to make room.
func (s *TelemetryOutboundStore) Enqueue(msg OutboundMessage) (evicted int64, err error) {
	createdAt := msg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	byteSize := msg.ByteSize
	if byteSize == 0 {
		byteSize = len(msg.Payload)
	}

	_, err = s.db.Exec(`
		INSERT INTO telemetry_outbound
			(snapshot_id, section, class, priority, batch_index, batch_count, payload, byte_size, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.SnapshotID, msg.Section, msg.Class, msg.Priority,
		msg.BatchIndex, msg.BatchCount, msg.Payload, byteSize,
		createdAt.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("enqueue telemetry message: %w", err)
	}
	return s.Prune()
}

// Prune enforces the retention bounds and returns the number of rows removed.
//
// Eviction order is oldest-lowest-priority first, so a burst of routine
// inventory can never push out a critical security event that has not yet been
// delivered.
func (s *TelemetryOutboundStore) Prune() (int64, error) {
	var total int64

	if s.limits.MaxAge > 0 {
		cutoff := time.Now().UTC().Add(-s.limits.MaxAge).Format(time.RFC3339)
		res, err := s.db.Exec(
			"DELETE FROM telemetry_outbound WHERE length(created_at) > 0 AND created_at < ?", cutoff)
		if err != nil {
			return total, fmt.Errorf("prune by age: %w", err)
		}
		if n, affErr := res.RowsAffected(); affErr == nil {
			total += n
		}
	}

	if s.limits.MaxRows > 0 {
		n, err := s.pruneByRows()
		if err != nil {
			return total, fmt.Errorf("prune by rows: %w", err)
		}
		total += n
	}

	if s.limits.MaxBytes > 0 {
		n, err := s.pruneByBytes()
		if err != nil {
			return total, fmt.Errorf("prune by bytes: %w", err)
		}
		total += n
	}

	return total, nil
}

// evictLowestPriority deletes up to n rows, choosing the lowest-priority and
// then oldest first. Priority is ascending-urgent, so ORDER BY priority DESC
// puts the least important rows at the front of the deletion set.
func (s *TelemetryOutboundStore) evictLowestPriority(n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	res, err := s.db.Exec(`
		DELETE FROM telemetry_outbound WHERE id IN (
			SELECT id FROM telemetry_outbound ORDER BY priority DESC, id ASC LIMIT ?
		)`, n)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		// The delete succeeded; only the count is unavailable.
		return 0, nil
	}
	return affected, nil
}

// pruneByRows evicts until the row count fits MaxRows.
func (s *TelemetryOutboundStore) pruneByRows() (int64, error) {
	var count int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM telemetry_outbound").Scan(&count); err != nil {
		return 0, err
	}
	excess := count - int64(s.limits.MaxRows)
	if excess <= 0 {
		return 0, nil
	}
	return s.evictLowestPriority(excess)
}

// pruneByBytes evicts until the total payload size fits MaxBytes.
func (s *TelemetryOutboundStore) pruneByBytes() (int64, error) {
	var total int64
	for {
		var sum sql.NullInt64
		if err := s.db.QueryRow("SELECT SUM(byte_size) FROM telemetry_outbound").Scan(&sum); err != nil {
			return total, err
		}
		if !sum.Valid || sum.Int64 <= s.limits.MaxBytes {
			return total, nil
		}
		n, err := s.evictLowestPriority(1)
		if err != nil {
			return total, err
		}
		if n == 0 {
			// Nothing left to remove; stop rather than spin.
			return total, nil
		}
		total += n
	}
}

// GetPending returns up to limit messages, most urgent first.
func (s *TelemetryOutboundStore) GetPending(limit int) ([]OutboundMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, snapshot_id, section, class, priority, batch_index, batch_count,
		       payload, byte_size, attempts, created_at
		FROM telemetry_outbound
		ORDER BY priority ASC, id ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending telemetry: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Printf("TelemetryOutboundStore: close rows: %v", closeErr)
		}
	}()

	var out []OutboundMessage
	for rows.Next() {
		var (
			m       OutboundMessage
			created []byte
		)
		if scanErr := rows.Scan(&m.ID, &m.SnapshotID, &m.Section, &m.Class, &m.Priority,
			&m.BatchIndex, &m.BatchCount, &m.Payload, &m.ByteSize, &m.Attempts, &created); scanErr != nil {
			return nil, fmt.Errorf("scan pending telemetry: %w", scanErr)
		}
		m.CreatedAt = derefTime(parseTime(created))
		out = append(out, m)
	}
	return out, rows.Err()
}

// Delete removes delivered messages by ID.
func (s *TelemetryOutboundStore) Delete(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin delete tx: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
			log.Printf("TelemetryOutboundStore: rollback: %v", rbErr)
		}
	}()

	stmt, err := tx.Prepare("DELETE FROM telemetry_outbound WHERE id = ?")
	if err != nil {
		return fmt.Errorf("prepare delete: %w", err)
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			log.Printf("TelemetryOutboundStore: close stmt: %v", closeErr)
		}
	}()

	for _, id := range ids {
		if _, execErr := stmt.Exec(id); execErr != nil {
			return fmt.Errorf("delete message %d: %w", id, execErr)
		}
	}
	return tx.Commit()
}

// IncrementAttempts records a delivery attempt for the given messages.
func (s *TelemetryOutboundStore) IncrementAttempts(ids []int64) error {
	for _, id := range ids {
		if _, err := s.db.Exec(
			"UPDATE telemetry_outbound SET attempts = attempts + 1 WHERE id = ?", id); err != nil {
			return fmt.Errorf("increment attempts for %d: %w", id, err)
		}
	}
	return nil
}

// Depth returns the number of queued messages, for telemetry health.
func (s *TelemetryOutboundStore) Depth() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM telemetry_outbound").Scan(&n)
	return n, err
}

// TotalBytes returns the queue's current payload size.
func (s *TelemetryOutboundStore) TotalBytes() (int64, error) {
	var sum sql.NullInt64
	if err := s.db.QueryRow("SELECT SUM(byte_size) FROM telemetry_outbound").Scan(&sum); err != nil {
		return 0, err
	}
	if !sum.Valid {
		return 0, nil
	}
	return sum.Int64, nil
}

// Close releases the database connection.
func (s *TelemetryOutboundStore) Close() error { return s.db.Close() }
