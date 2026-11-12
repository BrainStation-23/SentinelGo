package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"sentinelgo/internal/winsec"
	"sentinelgo/internal/yara"
)

// YARAEventsDBName is the threat hunting event queue's file, next to
// config.json.
const YARAEventsDBName = "sentinelgo_yara.db"

const yaraEventSchemaV1 = `
CREATE TABLE IF NOT EXISTS yara_event_queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT    NOT NULL,
    event_json TEXT    NOT NULL,
    bytes      INTEGER NOT NULL,
    stored_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_yara_event_id ON yara_event_queue(event_id);
CREATE TABLE IF NOT EXISTS yara_reported (
    key         TEXT    PRIMARY KEY,
    reported_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yara_reported_at ON yara_reported(reported_at);
CREATE TABLE IF NOT EXISTS yara_event_meta (
    key   TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
);
`

var yaraEventMigrations = []Migration{
	{Version: 1, SQL: yaraEventSchemaV1},
}

// Limits. An offline device drops its oldest events beyond the queue caps
// rather than growing without bound; drops are counted. Reported-match keys
// (device de-dup, #415) are kept for YARAReportedTTL, at most
// DefaultYARAMaxReported of them.
const (
	DefaultYARAMaxRows     = 50_000
	DefaultYARAMaxBytes    = 32 << 20
	DefaultYARAMaxReported = 200_000
	YARAReportedTTL        = 30 * 24 * time.Hour
)

// YARAEventStore is the SQLite queue of threat hunting events (matches and
// scan summaries) awaiting upload, plus the keys of matches already
// reported. Rows are deleted once the server has accepted (or for good
// rejected) them. The file is owner-only.
type YARAEventStore struct {
	db          *sql.DB
	maxRows     int
	maxBytes    int64
	maxReported int
	now         func() time.Time
}

// NewYARAEventStore opens (or creates) the queue at path.
func NewYARAEventStore(path string) (*YARAEventStore, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open YARA event store: %w", err)
	}
	if err := Migrate(db, yaraEventMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate YARA event store: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("YARA: could not restrict %s: %v", path, err)
	}
	if err := winsec.SecurePath(path); err != nil {
		log.Printf("YARA: could not restrict %s: %v", path, err)
	}
	return &YARAEventStore{db: db, maxRows: DefaultYARAMaxRows, maxBytes: DefaultYARAMaxBytes,
		maxReported: DefaultYARAMaxReported, now: time.Now}, nil
}

// SetLimits overrides the queue's row and byte caps and the reported-key
// cap (tests, tuning).
func (s *YARAEventStore) SetLimits(maxRows int, maxBytes int64, maxReported int) {
	s.maxRows, s.maxBytes, s.maxReported = maxRows, maxBytes, maxReported
}

// Add queues events. An event_id already queued is ignored.
func (s *YARAEventStore) Add(evs []yara.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin YARA event tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().Unix()
	for _, ev := range evs {
		data, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("encode YARA event: %w", err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO yara_event_queue (event_id, event_json, bytes, stored_at)
			VALUES (?, ?, ?, ?)`, ev.EventID, string(data), len(data), now); err != nil {
			return fmt.Errorf("insert YARA event: %w", err)
		}
	}
	if err := s.enforceCap(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// enforceCap deletes the oldest rows while the queue is over a cap, and adds
// them to the drop counter.
func (s *YARAEventStore) enforceCap(tx *sql.Tx) error {
	var rows int
	var bytes int64
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM yara_event_queue`).Scan(&rows, &bytes); err != nil {
		return fmt.Errorf("measure YARA queue: %w", err)
	}
	if rows <= s.maxRows && bytes <= s.maxBytes {
		return nil
	}
	r, err := tx.Query(`SELECT id, bytes FROM yara_event_queue ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list YARA queue: %w", err)
	}
	var drop []int64
	for r.Next() && (rows > s.maxRows || bytes > s.maxBytes) {
		var id, n int64
		if err := r.Scan(&id, &n); err != nil {
			_ = r.Close()
			return fmt.Errorf("scan YARA queue: %w", err)
		}
		drop = append(drop, id)
		rows--
		bytes -= n
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := deleteYARAEvents(tx, drop); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO yara_event_meta (key, value) VALUES ('dropped', ?)
		ON CONFLICT(key) DO UPDATE SET value = value + excluded.value`, len(drop)); err != nil {
		return fmt.Errorf("count dropped YARA events: %w", err)
	}
	log.Printf("YARA: event queue full, dropped the %d oldest events", len(drop))
	return nil
}

// YARAEventRow is a queued event and its row id.
type YARAEventRow struct {
	ID    int64
	Event yara.Event
}

// Pending returns up to limit queued events, oldest first. A row this agent
// can't read is deleted rather than blocking the queue.
func (s *YARAEventStore) Pending(limit int) ([]YARAEventRow, error) {
	rows, err := s.db.Query(`SELECT id, event_json FROM yara_event_queue ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query YARA events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []YARAEventRow
	var bad []int64
	for rows.Next() {
		var row YARAEventRow
		var data string
		if err := rows.Scan(&row.ID, &data); err != nil {
			return nil, fmt.Errorf("scan YARA event: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &row.Event); err != nil {
			log.Printf("YARA: dropping unreadable queued event (row %d)", row.ID)
			bad = append(bad, row.ID)
			continue
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close() // the pool has one connection
	if len(bad) > 0 {
		if err := s.Delete(bad); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Delete removes rows the server accepted or rejected for good.
func (s *YARAEventStore) Delete(ids []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := deleteYARAEvents(tx, ids); err != nil {
		return err
	}
	return tx.Commit()
}

func deleteYARAEvents(tx *sql.Tx, ids []int64) error {
	for len(ids) > 0 {
		n := min(len(ids), 500) // under SQLite's bound-parameter limit
		args := make([]any, n)
		for i, id := range ids[:n] {
			args[i] = id
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", n), ",")
		// #nosec G202 -- placeholders holds only "?" and ","; every id is a bound argument
		if _, err := tx.Exec("DELETE FROM yara_event_queue WHERE id IN ("+placeholders+")", args...); err != nil {
			return fmt.Errorf("delete YARA events: %w", err)
		}
		ids = ids[n:]
	}
	return nil
}

// Stats reports the queue depth and how many events were dropped over the
// caps since the queue was created.
func (s *YARAEventStore) Stats() (rows int, bytes int64, dropped int64, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM yara_event_queue`).Scan(&rows, &bytes); err != nil {
		return 0, 0, 0, err
	}
	err = s.db.QueryRow(`SELECT value FROM yara_event_meta WHERE key = 'dropped'`).Scan(&dropped)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return rows, bytes, dropped, err
}

// Reported returns which of keys were reported in the last YARAReportedTTL.
func (s *YARAEventStore) Reported(keys []string) (map[string]bool, error) {
	out := map[string]bool{}
	since := s.now().Add(-YARAReportedTTL).Unix()
	for len(keys) > 0 {
		n := min(len(keys), 500)
		args := make([]any, 0, n+1)
		for _, k := range keys[:n] {
			args = append(args, k)
		}
		args = append(args, since)
		placeholders := strings.TrimSuffix(strings.Repeat("?,", n), ",")
		// #nosec G202 -- placeholders holds only "?" and ","; every key is a bound argument
		rows, err := s.db.Query("SELECT key FROM yara_reported WHERE key IN ("+placeholders+") AND reported_at >= ?", args...)
		if err != nil {
			return nil, fmt.Errorf("query reported YARA matches: %w", err)
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				_ = rows.Close()
				return nil, err
			}
			out[k] = true
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		keys = keys[n:]
	}
	return out, nil
}

// MarkReported records keys as reported now, then drops keys older than
// YARAReportedTTL and the oldest beyond the cap.
func (s *YARAEventStore) MarkReported(keys []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().Unix()
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT INTO yara_reported (key, reported_at) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET reported_at = excluded.reported_at`, k, now); err != nil {
			return fmt.Errorf("mark YARA match reported: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM yara_reported WHERE reported_at < ?`, s.now().Add(-YARAReportedTTL).Unix()); err != nil {
		return fmt.Errorf("expire reported YARA matches: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM yara_reported WHERE key IN (
		SELECT key FROM yara_reported ORDER BY reported_at DESC, key LIMIT -1 OFFSET ?)`, s.maxReported); err != nil {
		return fmt.Errorf("cap reported YARA matches: %w", err)
	}
	return tx.Commit()
}

// Close closes the database.
func (s *YARAEventStore) Close() error { return s.db.Close() }
