package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// TelemetryStateDBName is the filename of the telemetry state database, placed
// alongside config.json like the other agent stores.
const TelemetryStateDBName = "sentinelgo_telemetry.db"

// telemetryStateSchemaV1 stores reconciliation state ONLY.
//
// There is deliberately no payload column. Change detection needs a hash and a
// few timestamps; keeping full inventory here would put a device's complete
// hardware, network, user and security profile on disk indefinitely for no
// operational gain. Payloads live in the outbound queue only while in flight,
// and are deleted once delivered.
const telemetryStateSchemaV1 = `
CREATE TABLE IF NOT EXISTS telemetry_section_state (
	section            TEXT    PRIMARY KEY,
	schema_version     INTEGER NOT NULL DEFAULT 0,
	hash               TEXT    NOT NULL DEFAULT '',
	item_count         INTEGER NOT NULL DEFAULT 0,
	status             TEXT    NOT NULL DEFAULT '',
	last_collected_at  TEXT    NOT NULL DEFAULT '',
	last_uploaded_at   TEXT    NOT NULL DEFAULT '',
	last_reconciled_at TEXT    NOT NULL DEFAULT ''
);
`

var telemetryStateMigrations = []Migration{
	{Version: 1, SQL: telemetryStateSchemaV1},
}

// SectionState is the persisted reconciliation state of one telemetry section.
type SectionState struct {
	Section          string
	SchemaVersion    int
	Hash             string
	ItemCount        int
	Status           string
	LastCollectedAt  time.Time
	LastUploadedAt   time.Time
	LastReconciledAt time.Time
}

// TelemetryStateStore persists per-section hashes and timestamps.
//
// Persisting this state (rather than holding it in memory) is what makes an
// agent restart cheap: without it, every restart looks like a first run and
// re-uploads everything.
type TelemetryStateStore struct {
	db *sql.DB
}

// NewTelemetryStateStore opens (or creates) the database at dbPath and applies
// migrations. The caller is responsible for closing the store.
func NewTelemetryStateStore(dbPath string) (*TelemetryStateStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open telemetry state store: %w", err)
	}
	if err := Migrate(db, telemetryStateMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate telemetry state store: %w", err)
	}
	return &TelemetryStateStore{db: db}, nil
}

// Get returns the stored state for a section, or nil when it has none yet.
func (s *TelemetryStateStore) Get(section string) (*SectionState, error) {
	row := s.db.QueryRow(`
		SELECT section, schema_version, hash, item_count, status,
		       last_collected_at, last_uploaded_at, last_reconciled_at
		FROM telemetry_section_state WHERE section = ?`, section)

	var (
		st                            SectionState
		collected, uploaded, reconcil []byte
	)
	err := row.Scan(&st.Section, &st.SchemaVersion, &st.Hash, &st.ItemCount,
		&st.Status, &collected, &uploaded, &reconcil)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query section state %q: %w", section, err)
	}

	st.LastCollectedAt = derefTime(parseTime(collected))
	st.LastUploadedAt = derefTime(parseTime(uploaded))
	st.LastReconciledAt = derefTime(parseTime(reconcil))
	return &st, nil
}

// GetAll returns every stored section state, keyed by section name.
func (s *TelemetryStateStore) GetAll() (map[string]*SectionState, error) {
	rows, err := s.db.Query(`
		SELECT section, schema_version, hash, item_count, status,
		       last_collected_at, last_uploaded_at, last_reconciled_at
		FROM telemetry_section_state ORDER BY section`)
	if err != nil {
		return nil, fmt.Errorf("query section states: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("TelemetryStateStore: close rows: %v", err)
		}
	}()

	out := make(map[string]*SectionState)
	for rows.Next() {
		var (
			st                            SectionState
			collected, uploaded, reconcil []byte
		)
		if err := rows.Scan(&st.Section, &st.SchemaVersion, &st.Hash, &st.ItemCount,
			&st.Status, &collected, &uploaded, &reconcil); err != nil {
			return nil, fmt.Errorf("scan section state: %w", err)
		}
		st.LastCollectedAt = derefTime(parseTime(collected))
		st.LastUploadedAt = derefTime(parseTime(uploaded))
		st.LastReconciledAt = derefTime(parseTime(reconcil))
		out[st.Section] = &st
	}
	return out, rows.Err()
}

// MarkCollected records a collection result without implying an upload.
func (s *TelemetryStateStore) MarkCollected(section string, schemaVersion int, hash string, itemCount int, status string, at time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO telemetry_section_state
			(section, schema_version, hash, item_count, status, last_collected_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(section) DO UPDATE SET
			schema_version    = excluded.schema_version,
			hash              = excluded.hash,
			item_count        = excluded.item_count,
			status            = excluded.status,
			last_collected_at = excluded.last_collected_at`,
		section, schemaVersion, hash, itemCount, status, formatTimeValue(at))
	if err != nil {
		return fmt.Errorf("mark collected %q: %w", section, err)
	}
	return nil
}

// MarkUploaded records a successful upload, advancing the reconcile clock.
//
// Both timestamps move together: the reconcile interval measures time since the
// backend last saw the section, so it must only advance on delivery, never on
// collection.
func (s *TelemetryStateStore) MarkUploaded(section string, at time.Time) error {
	ts := formatTimeValue(at)
	res, err := s.db.Exec(`
		UPDATE telemetry_section_state
		SET last_uploaded_at = ?, last_reconciled_at = ?
		WHERE section = ?`, ts, ts, section)
	if err != nil {
		return fmt.Errorf("mark uploaded %q: %w", section, err)
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return fmt.Errorf("mark uploaded %q: no such section state", section)
	}
	return nil
}

// Delete removes a section's state, forcing a fresh full upload next cycle.
func (s *TelemetryStateStore) Delete(section string) error {
	_, err := s.db.Exec("DELETE FROM telemetry_section_state WHERE section = ?", section)
	return err
}

// Reset clears all state. Used by the CLI to force a full resync.
func (s *TelemetryStateStore) Reset() error {
	_, err := s.db.Exec("DELETE FROM telemetry_section_state")
	return err
}

// Close releases the database connection.
func (s *TelemetryStateStore) Close() error { return s.db.Close() }

// formatTimeValue renders t as RFC3339 UTC, or "" for the zero time.
func formatTimeValue(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// derefTime turns a *time.Time into a value, using the zero time for nil.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
