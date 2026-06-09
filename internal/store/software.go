package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"sentinelgo/internal/models"
)

const softwareCatalogSchemaV1 = `
CREATE TABLE IF NOT EXISTS software_catalog (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    name              TEXT     NOT NULL,
    source            TEXT     NOT NULL,
    type              TEXT     NOT NULL DEFAULT '',
    installed_version TEXT     NOT NULL DEFAULT '',
    display_name      TEXT     NOT NULL DEFAULT '',
    software_package  TEXT     NOT NULL DEFAULT '',
    app_store_app     TEXT     NOT NULL DEFAULT '',
    last_opened       TEXT     NOT NULL DEFAULT '',
    file_path         TEXT     NOT NULL DEFAULT '',
    status            TEXT     NOT NULL DEFAULT 'installed',
    is_active         INTEGER  NOT NULL DEFAULT 1,
    first_seen_at     TEXT     NOT NULL,
    last_seen_at      TEXT     NOT NULL,
    UNIQUE(name, source)
);
CREATE INDEX IF NOT EXISTS idx_sw_status    ON software_catalog(status);
CREATE INDEX IF NOT EXISTS idx_sw_last_seen ON software_catalog(last_seen_at);
`

// software_sync_queue tracks whether the catalog has pending changes that have not yet been
// successfully sent to Supabase. One row per sync cycle; deleted on successful upload.
const softwareSyncQueueSchemaV2 = `
CREATE TABLE IF NOT EXISTS software_sync_queue (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    queued_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

var softwareMigrations = []Migration{
	{Version: 1, SQL: softwareCatalogSchemaV1},
	{Version: 2, SQL: softwareSyncQueueSchemaV2},
}

// SoftwareStore is a SQLite-backed catalog of installed (and previously installed) software.
// It tracks install/uninstall status by comparing each fresh scan against stored records,
// and maintains a lightweight sync queue so failed Supabase uploads are retried.
type SoftwareStore struct {
	db *sql.DB
}

// NewSoftwareStore opens (or creates) the SQLite database at path and runs schema migrations.
func NewSoftwareStore(path string) (*SoftwareStore, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open software store: %w", err)
	}

	if err := Migrate(db, softwareMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate software store: %w", err)
	}

	return &SoftwareStore{db: db}, nil
}

// SyncBatch reconciles the fresh scan result against the stored catalog in a single transaction:
//  1. Upserts every item in items: status=installed, is_active=1, last_seen_at=syncTime.
//     first_seen_at is set only on INSERT (preserved on UPDATE).
//  2. Marks any row that is still status=installed but has last_seen_at < syncTime as
//     uninstalled (status=uninstalled, is_active=0). These entries were not in the scan.
//
// After a successful SyncBatch, call QueueSync to mark the catalog as needing upload.
func (s *SoftwareStore) SyncBatch(items []models.SoftwareInfo, syncTime time.Time) error {
	syncTimeStr := syncTime.UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin software sync tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	upsert, err := tx.Prepare(`
		INSERT INTO software_catalog
			(name, source, type, installed_version, display_name, software_package,
			 app_store_app, last_opened, file_path, status, is_active, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'installed', 1, ?, ?)
		ON CONFLICT(name, source) DO UPDATE SET
			type              = excluded.type,
			installed_version = excluded.installed_version,
			display_name      = excluded.display_name,
			software_package  = excluded.software_package,
			app_store_app     = excluded.app_store_app,
			last_opened       = excluded.last_opened,
			file_path         = excluded.file_path,
			status            = 'installed',
			is_active         = 1,
			last_seen_at      = excluded.last_seen_at
	`)
	if err != nil {
		return fmt.Errorf("prepare upsert: %w", err)
	}
	defer func() {
		if err := upsert.Close(); err != nil {
			log.Printf("SoftwareStore: close upsert stmt: %v", err)
		}
	}()

	for _, sw := range items {
		if _, err := upsert.Exec(
			sw.Name, sw.Source, sw.Type, sw.InstalledVersion,
			sw.DisplayName, sw.SoftwarePackage, sw.AppStoreApp,
			sw.LastOpened, sw.FilePath,
			syncTimeStr,
			syncTimeStr,
		); err != nil {
			return fmt.Errorf("upsert software %q: %w", sw.Name, err)
		}
	}

	if _, err := tx.Exec(`
		UPDATE software_catalog
		   SET status = 'uninstalled', is_active = 0
		 WHERE status = 'installed' AND last_seen_at < ?
	`, syncTimeStr); err != nil {
		return fmt.Errorf("mark uninstalled: %w", err)
	}

	return tx.Commit()
}

// GetAll returns the full software catalog (installed and uninstalled entries).
func (s *SoftwareStore) GetAll() ([]models.SoftwareInfo, error) {
	rows, err := s.db.Query(`
		SELECT id, name, source, type, installed_version, display_name,
		       software_package, app_store_app, last_opened, file_path,
		       status, is_active, first_seen_at, last_seen_at
		FROM software_catalog
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query software catalog: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("SoftwareStore: close rows: %v", err)
		}
	}()

	var result []models.SoftwareInfo
	for rows.Next() {
		var sw models.SoftwareInfo
		var isActive int
		if err := rows.Scan(
			&sw.ID, &sw.Name, &sw.Source, &sw.Type, &sw.InstalledVersion,
			&sw.DisplayName, &sw.SoftwarePackage, &sw.AppStoreApp,
			&sw.LastOpened, &sw.FilePath,
			&sw.Status, &isActive, &sw.FirstSeenAt, &sw.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan software row: %w", err)
		}
		sw.IsActive = isActive == 1
		result = append(result, sw)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate software rows: %w", err)
	}

	return result, nil
}

// QueueSync records that the catalog has been updated and needs to be uploaded to Supabase.
func (s *SoftwareStore) QueueSync() error {
	_, err := s.db.Exec("INSERT INTO software_sync_queue (queued_at) VALUES (CURRENT_TIMESTAMP)")
	return err
}

// HasPendingSync reports whether there are unuploaded catalog changes.
func (s *SoftwareStore) HasPendingSync() (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM software_sync_queue").Scan(&count)
	return count > 0, err
}

// ClearSync removes all pending sync markers after a successful Supabase upload.
func (s *SoftwareStore) ClearSync() error {
	_, err := s.db.Exec("DELETE FROM software_sync_queue")
	return err
}

// Close closes the underlying database connection.
func (s *SoftwareStore) Close() error {
	return s.db.Close()
}
