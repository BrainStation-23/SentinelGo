package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/dlp/events"
)

// DLPEventsDBName is the DLP evidence queue's file, next to config.json.
const DLPEventsDBName = "sentinelgo_dlp.db"

const dlpEventSchemaV1 = `
CREATE TABLE IF NOT EXISTS dlp_event_queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT    NOT NULL,
    dedupe_key   TEXT    NOT NULL,
    event_json   TEXT    NOT NULL,
    repeat_count INTEGER NOT NULL DEFAULT 1,
    bytes        INTEGER NOT NULL,
    stored_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dlp_event_id     ON dlp_event_queue(event_id);
CREATE INDEX        IF NOT EXISTS idx_dlp_event_dedupe ON dlp_event_queue(dedupe_key, stored_at);
CREATE TABLE IF NOT EXISTS dlp_event_meta (
    key   TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
);
`

var dlpEventMigrations = []Migration{
	{Version: 1, SQL: dlpEventSchemaV1},
}

// Queue limits. An offline device drops its oldest events beyond these
// rather than growing without bound; drops are counted.
const (
	DefaultDLPMaxRows  = 10_000
	DefaultDLPMaxBytes = 20 << 20

	// DLPDedupeWindow: the same content under the same policy within this
	// window bumps repeat_count on the queued event instead of adding one.
	DLPDedupeWindow = 60 * time.Second
)

// DLPEventStore is the SQLite queue of DLP evidence events awaiting upload.
// Rows are deleted only once the server has accepted them.
type DLPEventStore struct {
	db       *sql.DB
	maxRows  int
	maxBytes int64
	now      func() time.Time
}

// NewDLPEventStore opens (or creates) the queue at path.
func NewDLPEventStore(path string) (*DLPEventStore, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open DLP event store: %w", err)
	}
	if err := Migrate(db, dlpEventMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate DLP event store: %w", err)
	}
	return &DLPEventStore{db: db, maxRows: DefaultDLPMaxRows, maxBytes: DefaultDLPMaxBytes, now: time.Now}, nil
}

// SetLimits overrides the row and byte caps (tests, tuning).
func (s *DLPEventStore) SetLimits(maxRows int, maxBytes int64) {
	s.maxRows, s.maxBytes = maxRows, maxBytes
}

// Add queues ev, or bumps repeat_count on a queued event with the same
// content and policy from the last DLPDedupeWindow. It reports whether ev was
// merged into an existing row.
func (s *DLPEventStore) Add(ev events.Event) (merged bool, err error) {
	data, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("encode DLP event: %w", err)
	}
	now := s.now().Unix()

	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin DLP event tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`UPDATE dlp_event_queue SET repeat_count = repeat_count + 1
		WHERE id = (SELECT id FROM dlp_event_queue WHERE dedupe_key = ? AND stored_at >= ? ORDER BY id DESC LIMIT 1)`,
		ev.DedupeKey(), now-int64(DLPDedupeWindow/time.Second))
	if err != nil {
		return false, fmt.Errorf("dedupe DLP event: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, tx.Commit()
	}

	if _, err := tx.Exec(`INSERT OR IGNORE INTO dlp_event_queue
		(event_id, dedupe_key, event_json, repeat_count, bytes, stored_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ev.EventID, ev.DedupeKey(), string(data), max(1, ev.RepeatCount), len(data), now); err != nil {
		return false, fmt.Errorf("insert DLP event: %w", err)
	}
	if err := s.enforceCap(tx); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

// enforceCap deletes the oldest rows while the queue is over its row or byte
// cap, and adds them to the drop counter.
func (s *DLPEventStore) enforceCap(tx *sql.Tx) error {
	var rows int
	var bytes int64
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM dlp_event_queue`).Scan(&rows, &bytes); err != nil {
		return fmt.Errorf("measure DLP queue: %w", err)
	}
	if rows <= s.maxRows && bytes <= s.maxBytes {
		return nil
	}

	r, err := tx.Query(`SELECT id, bytes FROM dlp_event_queue ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list DLP queue: %w", err)
	}
	var drop []int64
	for r.Next() && (rows > s.maxRows || bytes > s.maxBytes) {
		var id, n int64
		if err := r.Scan(&id, &n); err != nil {
			_ = r.Close()
			return fmt.Errorf("scan DLP queue: %w", err)
		}
		drop = append(drop, id)
		rows--
		bytes -= n
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := deleteDLPEvents(tx, drop); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO dlp_event_meta (key, value) VALUES ('dropped', ?)
		ON CONFLICT(key) DO UPDATE SET value = value + excluded.value`, len(drop)); err != nil {
		return fmt.Errorf("count dropped DLP events: %w", err)
	}
	log.Printf("DLP: event queue full, dropped the %d oldest events", len(drop))
	return nil
}

// DLPEventRow is a queued event and its row id.
type DLPEventRow struct {
	ID    int64
	Event events.Event
}

// Pending returns up to limit queued events, oldest first, with their current
// repeat_count.
func (s *DLPEventStore) Pending(limit int) ([]DLPEventRow, error) {
	rows, err := s.db.Query(`SELECT id, event_json, repeat_count FROM dlp_event_queue ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query DLP events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []DLPEventRow
	for rows.Next() {
		var row DLPEventRow
		var data string
		var repeats int
		if err := rows.Scan(&row.ID, &data, &repeats); err != nil {
			return nil, fmt.Errorf("scan DLP event: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &row.Event); err != nil {
			// Can't happen for rows we wrote; skip rather than block the queue.
			log.Printf("DLP: dropping unreadable queued event %d: %v", row.ID, err)
			_ = s.Delete([]int64{row.ID})
			continue
		}
		row.Event.RepeatCount = repeats
		out = append(out, row)
	}
	return out, rows.Err()
}

// Delete removes rows the server has accepted (or rejected for good).
func (s *DLPEventStore) Delete(ids []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := deleteDLPEvents(tx, ids); err != nil {
		return err
	}
	return tx.Commit()
}

func deleteDLPEvents(tx *sql.Tx, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	// #nosec G202 -- placeholders holds only "?" and ","; every id is a bound argument
	if _, err := tx.Exec("DELETE FROM dlp_event_queue WHERE id IN ("+placeholders+")", args...); err != nil {
		return fmt.Errorf("delete DLP events: %w", err)
	}
	return nil
}

// Stats reports the queue depth and how many events were dropped over the
// cap since the queue was created.
func (s *DLPEventStore) Stats() (rows int, bytes int64, dropped int64, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM dlp_event_queue`).Scan(&rows, &bytes); err != nil {
		return 0, 0, 0, err
	}
	err = s.db.QueryRow(`SELECT value FROM dlp_event_meta WHERE key = 'dropped'`).Scan(&dropped)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return rows, bytes, dropped, err
}

// Close closes the database.
func (s *DLPEventStore) Close() error {
	return s.db.Close()
}
