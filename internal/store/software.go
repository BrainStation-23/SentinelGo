package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

// SoftwareDBName is the filename of the local software catalog, placed alongside
// config.json. Shared so the scheduler and the force-sync task agree on the path.
const SoftwareDBName = "sentinelgo_software.db"

const softwareSchemaV1 = `
CREATE TABLE IF NOT EXISTS software (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	agent_id          TEXT    NOT NULL,
	name              TEXT    NOT NULL,
	source            TEXT    NOT NULL DEFAULT '',
	type              TEXT    NOT NULL DEFAULT '',
	installed_version TEXT    NOT NULL DEFAULT '',
	display_name      TEXT    NOT NULL DEFAULT '',
	software_package  TEXT    NOT NULL DEFAULT '',
	app_store_app     TEXT    NOT NULL DEFAULT '',
	last_opened       TEXT    NOT NULL DEFAULT '',
	file_path         TEXT    NOT NULL DEFAULT '',
	first_seen_at     TEXT    NOT NULL DEFAULT '',
	updated_at        TEXT    NOT NULL DEFAULT '',
	UNIQUE(agent_id, name, source)
);
CREATE INDEX IF NOT EXISTS idx_software_agent ON software(agent_id);
`

var softwareMigrations = []Migration{
	{Version: 1, SQL: softwareSchemaV1},
}

// SoftwareStore is a SQLite-backed local cache for installed-software state.
type SoftwareStore struct {
	db *sql.DB
}

// NewSoftwareStore opens (or creates) the SQLite database at dbPath and applies
// schema migrations. The caller is responsible for closing the store.
func NewSoftwareStore(dbPath string) (*SoftwareStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open software store: %w", err)
	}

	if err := Migrate(db, softwareMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate software store: %w", err)
	}

	return &SoftwareStore{db: db}, nil
}

// Upsert inserts or updates software entries for agentID. first_seen_at is
// preserved on update so the original discovery timestamp is never overwritten.
func (s *SoftwareStore) Upsert(agentID string, items []models.SoftwareInfo) error {
	if len(items) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin upsert tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("SoftwareStore: rollback: %v", err)
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)

	stmt, err := tx.Prepare(`
		INSERT INTO software
			(agent_id, name, source, type, installed_version, display_name, software_package, app_store_app, last_opened, file_path, first_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, name, source) DO UPDATE SET
			type              = excluded.type,
			installed_version = excluded.installed_version,
			display_name      = excluded.display_name,
			software_package  = excluded.software_package,
			app_store_app     = excluded.app_store_app,
			last_opened       = excluded.last_opened,
			file_path         = excluded.file_path,
			updated_at        = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare upsert stmt: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("SoftwareStore: close stmt: %v", err)
		}
	}()

	for _, sw := range items {
		firstSeen := sw.FirstSeenAt
		if firstSeen == "" {
			firstSeen = now
		}
		_, err := stmt.Exec(
			agentID, sw.Name, sw.Source, sw.Type, sw.InstalledVersion,
			sw.DisplayName, sw.SoftwarePackage, sw.AppStoreApp, sw.LastOpened,
			sw.FilePath, firstSeen, now,
		)
		if err != nil {
			return fmt.Errorf("upsert software %q: %w", sw.Name, err)
		}
	}

	return tx.Commit()
}

// GetAll returns all software stored for agentID.
func (s *SoftwareStore) GetAll(agentID string) ([]models.SoftwareInfo, error) {
	rows, err := s.db.Query(`
		SELECT name, source, type, installed_version, display_name, software_package, app_store_app, last_opened, file_path, first_seen_at
		FROM software
		WHERE agent_id = ?
		ORDER BY source, name
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("query software: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("SoftwareStore: close rows: %v", err)
		}
	}()

	var items []models.SoftwareInfo
	for rows.Next() {
		var sw models.SoftwareInfo
		if err := rows.Scan(
			&sw.Name, &sw.Source, &sw.Type, &sw.InstalledVersion, &sw.DisplayName,
			&sw.SoftwarePackage, &sw.AppStoreApp, &sw.LastOpened, &sw.FilePath, &sw.FirstSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan software: %w", err)
		}
		items = append(items, sw)
	}
	return items, rows.Err()
}

// DeleteNotIn removes software for agentID whose (name, source) key is not in
// activeKeys. activeKeys entries are "<name>\x00<source>". This prunes
// uninstalled entries after a complete scan; callers must not invoke it after a
// partial scan or live software would be dropped.
func (s *SoftwareStore) DeleteNotIn(agentID string, activeKeys []string) error {
	if len(activeKeys) == 0 {
		_, err := s.db.Exec("DELETE FROM software WHERE agent_id = ?", agentID)
		return err
	}

	placeholders := make([]string, len(activeKeys))
	args := make([]any, 0, len(activeKeys)+1)
	args = append(args, agentID)
	for i, k := range activeKeys {
		placeholders[i] = "?"
		args = append(args, k)
	}

	const base = "DELETE FROM software WHERE agent_id = ? AND (name || char(0) || source) NOT IN ("
	query := base + strings.Join(placeholders, ",") + ")"
	_, err := s.db.Exec(query, args...)
	return err
}

// Close releases the database connection.
func (s *SoftwareStore) Close() error {
	return s.db.Close()
}
