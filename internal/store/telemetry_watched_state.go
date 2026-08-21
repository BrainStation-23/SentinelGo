package store

import (
	"fmt"
	"log"
	"time"
)

// telemetryStateSchemaV3 adds Phase G's change-detection state.
//
// It lives in the telemetry STATE database, not the outbound queue, because it
// is exactly the same kind of thing as telemetry_section_state: small,
// long-lived bookkeeping that must survive a restart, with no payload in it.
// Putting it in the queue database would tie a device's change history to the
// lifetime of messages that get deleted on delivery.
//
// Like the section-state table, there is deliberately no payload column. A row
// holds one watched value — a scalar, or one set member's present/absent flag —
// never the section it was derived from.
const telemetryStateSchemaV3 = `
CREATE TABLE IF NOT EXISTS telemetry_watched_state (
	watch_key         TEXT    PRIMARY KEY,
	section           TEXT    NOT NULL DEFAULT '',
	value_json        TEXT    NOT NULL DEFAULT '',
	observed_at       TEXT    NOT NULL DEFAULT '',
	changed_at        TEXT    NOT NULL DEFAULT '',
	pending_json      TEXT    NOT NULL DEFAULT '',
	pending_since     TEXT    NOT NULL DEFAULT '',
	last_event_at     TEXT    NOT NULL DEFAULT '',
	flap_count        INTEGER NOT NULL DEFAULT 0,
	flap_window_start TEXT    NOT NULL DEFAULT '',
	flap_alerted_at   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tel_watched_section ON telemetry_watched_state(section);
`

// WatchedStateRow is one persisted watched value.
//
// Values are carried as their encoded JSON string so the store stays free of
// any knowledge of the telemetry package's value model — the same separation
// the section-state table keeps.
type WatchedStateRow struct {
	Key             string
	Section         string
	ValueJSON       string
	ObservedAt      time.Time
	ChangedAt       time.Time
	PendingJSON     string
	PendingSince    time.Time
	LastEventAt     time.Time
	FlapCount       int
	FlapWindowStart time.Time
	FlapAlertedAt   time.Time
}

// GetAllWatched returns every stored watched value, keyed by watch key.
func (s *TelemetryStateStore) GetAllWatched() (map[string]*WatchedStateRow, error) {
	rows, err := s.db.Query(`
		SELECT watch_key, section, value_json, observed_at, changed_at,
		       pending_json, pending_since, last_event_at,
		       flap_count, flap_window_start, flap_alerted_at
		FROM telemetry_watched_state ORDER BY watch_key`)
	if err != nil {
		return nil, fmt.Errorf("query watched state: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Printf("TelemetryStateStore: close watched rows: %v", closeErr)
		}
	}()

	out := make(map[string]*WatchedStateRow)
	for rows.Next() {
		var (
			r                                     WatchedStateRow
			observed, changed, pending, lastEvent []byte
			flapWindowStart, flapAlerted          []byte
			flapCount                             int
		)
		if scanErr := rows.Scan(&r.Key, &r.Section, &r.ValueJSON, &observed, &changed,
			&r.PendingJSON, &pending, &lastEvent,
			&flapCount, &flapWindowStart, &flapAlerted); scanErr != nil {
			return nil, fmt.Errorf("scan watched state: %w", scanErr)
		}
		r.ObservedAt = derefTime(parseTime(observed))
		r.ChangedAt = derefTime(parseTime(changed))
		r.PendingSince = derefTime(parseTime(pending))
		r.LastEventAt = derefTime(parseTime(lastEvent))
		r.FlapWindowStart = derefTime(parseTime(flapWindowStart))
		r.FlapAlertedAt = derefTime(parseTime(flapAlerted))
		r.FlapCount = flapCount
		out[r.Key] = &r
	}
	return out, rows.Err()
}

// PutWatched inserts or replaces one watched value.
func (s *TelemetryStateStore) PutWatched(r *WatchedStateRow) error {
	if r == nil || r.Key == "" {
		return fmt.Errorf("put watched state: empty watch key")
	}
	_, err := s.db.Exec(`
		INSERT INTO telemetry_watched_state
			(watch_key, section, value_json, observed_at, changed_at,
			 pending_json, pending_since, last_event_at,
			 flap_count, flap_window_start, flap_alerted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(watch_key) DO UPDATE SET
			section           = excluded.section,
			value_json        = excluded.value_json,
			observed_at       = excluded.observed_at,
			changed_at        = excluded.changed_at,
			pending_json      = excluded.pending_json,
			pending_since     = excluded.pending_since,
			last_event_at     = excluded.last_event_at,
			flap_count        = excluded.flap_count,
			flap_window_start = excluded.flap_window_start,
			flap_alerted_at   = excluded.flap_alerted_at`,
		r.Key, r.Section, r.ValueJSON,
		formatTimeValue(r.ObservedAt), formatTimeValue(r.ChangedAt),
		r.PendingJSON, formatTimeValue(r.PendingSince), formatTimeValue(r.LastEventAt),
		r.FlapCount, formatTimeValue(r.FlapWindowStart), formatTimeValue(r.FlapAlertedAt))
	if err != nil {
		return fmt.Errorf("put watched state %q: %w", r.Key, err)
	}
	return nil
}

// DeleteWatched removes one watched value.
func (s *TelemetryStateStore) DeleteWatched(key string) error {
	if _, err := s.db.Exec("DELETE FROM telemetry_watched_state WHERE watch_key = ?", key); err != nil {
		return fmt.Errorf("delete watched state %q: %w", key, err)
	}
	return nil
}

// WatchedDepth returns how many watched values are stored.
func (s *TelemetryStateStore) WatchedDepth() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM telemetry_watched_state").Scan(&n)
	return n, err
}

// ResetWatched clears all change-detection state, so the next cycle re-seeds
// every baseline and reports nothing.
//
// Kept separate from Reset (which clears section reconciliation) because the
// two answer different questions. Re-sending inventory the backend already has
// is harmless; re-seeding watched state means the agent forgets what the device
// looked like, and any change that happens while it is forgotten goes
// unreported. That should be a deliberate, separately-named action.
func (s *TelemetryStateStore) ResetWatched() (int64, error) {
	res, err := s.db.Exec("DELETE FROM telemetry_watched_state")
	if err != nil {
		return 0, fmt.Errorf("reset watched state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return n, nil
}
