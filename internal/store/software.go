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

// missed_scans counts how many consecutive authoritative scans of a row's source
// have not seen that row. It debounces uninstall detection: a row is demoted only
// after uninstallConfirmThreshold consecutive misses, so a single spurious empty
// or partial scan cannot wipe a source. See SyncBatch.
const softwareMissedScansSchemaV3 = `
ALTER TABLE software_catalog ADD COLUMN missed_scans INTEGER NOT NULL DEFAULT 0;
`

var softwareMigrations = []Migration{
	{Version: 1, SQL: softwareCatalogSchemaV1},
	{Version: 2, SQL: softwareSyncQueueSchemaV2},
	{Version: 3, SQL: softwareMissedScansSchemaV3},
}

// uninstallConfirmThreshold is the number of consecutive authoritative scans a
// previously-installed row must be absent from before it is marked uninstalled.
// This mirrors the scheduler's consecutive-failure idiom (taskFailureThreshold):
// a negative signal (absence) is confirmed across cycles rather than trusted on a
// single scan, so a transient empty/partial enumeration that still exits 0 cannot
// demote a whole source. A genuine uninstall is reflected after this many cycles
// (~threshold x the software-sync interval).
const uninstallConfirmThreshold = 2

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
//  1. Upserts every item in items: status=installed, is_active=1, missed_scans=0,
//     last_seen_at=syncTime. first_seen_at is set only on INSERT (preserved on UPDATE),
//     using the item's own FirstSeenAt (the real install date when the collector knows it)
//     and falling back to syncTime otherwise.
//  2. For each source in scannedSources, increments missed_scans on every still-installed
//     row of that source that was not seen this cycle (last_seen_at < syncTime), then marks
//     as uninstalled (status=uninstalled, is_active=0) any row whose missed_scans has reached
//     uninstallConfirmThreshold.
//
// Reconciliation is scoped per source so that a scan which failed (or never ran) for a
// given source never touches that source's rows. In particular, if scannedSources is
// empty (every collector failed), nothing is incremented or demoted and the last-known
// catalog is preserved for the next retry.
//
// Uninstall is debounced via missed_scans: a single authoritative-but-spurious scan
// (exit 0 yet empty or truncated) only bumps the miss counter; the counter resets to 0
// the moment the software reappears (the upsert above), so only software genuinely absent
// for uninstallConfirmThreshold consecutive scans is demoted. This is what makes a
// transient enumeration glitch unable to wipe a source to "uninstalled".
//
// After a successful SyncBatch, call QueueSync to mark the catalog as needing upload.
func (s *SoftwareStore) SyncBatch(items []models.SoftwareInfo, syncTime time.Time, scannedSources map[string]bool) error {
	syncTimeStr := syncTime.UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin software sync tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertSoftware(tx, items, syncTimeStr); err != nil {
		return err
	}
	if err := reconcileScannedSources(tx, scannedSources, syncTimeStr); err != nil {
		return err
	}

	return tx.Commit()
}

// upsertSoftware inserts or refreshes every scanned item: status=installed,
// is_active=1, missed_scans=0, last_seen_at=syncTime. first_seen_at is set only on
// INSERT, preferring the collector's real install date (e.g. rpm INSTALLTIME,
// Windows InstallDate) and falling back to syncTime; on conflict it is preserved.
func upsertSoftware(tx *sql.Tx, items []models.SoftwareInfo, syncTimeStr string) error {
	upsert, err := tx.Prepare(`
		INSERT INTO software_catalog
			(name, source, type, installed_version, display_name, software_package,
			 app_store_app, last_opened, file_path, status, is_active, missed_scans,
			 first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'installed', 1, 0, ?, ?)
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
			missed_scans      = 0,
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
		firstSeen := sw.FirstSeenAt
		if firstSeen == "" {
			firstSeen = syncTimeStr
		}
		if _, err := upsert.Exec(
			sw.Name, sw.Source, sw.Type, sw.InstalledVersion,
			sw.DisplayName, sw.SoftwarePackage, sw.AppStoreApp,
			sw.LastOpened, sw.FilePath,
			firstSeen,
			syncTimeStr,
		); err != nil {
			return fmt.Errorf("upsert software %q: %w", sw.Name, err)
		}
	}
	return nil
}

// reconcileScannedSources debounces uninstall detection for each authoritatively
// scanned source: it increments missed_scans on every still-installed row of that
// source not seen this cycle (last_seen_at < syncTime), then demotes any row whose
// missed_scans has reached uninstallConfirmThreshold. Sources absent from
// scannedSources are never touched, so a failed (or never-run) scan preserves its rows.
func reconcileScannedSources(tx *sql.Tx, scannedSources map[string]bool, syncTimeStr string) error {
	miss, err := tx.Prepare(`
		UPDATE software_catalog
		   SET missed_scans = missed_scans + 1
		 WHERE status = 'installed' AND source = ? AND last_seen_at < ?
	`)
	if err != nil {
		return fmt.Errorf("prepare miss-counter: %w", err)
	}
	defer func() {
		if err := miss.Close(); err != nil {
			log.Printf("SoftwareStore: close miss stmt: %v", err)
		}
	}()

	demote, err := tx.Prepare(`
		UPDATE software_catalog
		   SET status = 'uninstalled', is_active = 0
		 WHERE status = 'installed' AND source = ? AND missed_scans >= ?
	`)
	if err != nil {
		return fmt.Errorf("prepare demote: %w", err)
	}
	defer func() {
		if err := demote.Close(); err != nil {
			log.Printf("SoftwareStore: close demote stmt: %v", err)
		}
	}()

	for source := range scannedSources {
		if _, err := miss.Exec(source, syncTimeStr); err != nil {
			return fmt.Errorf("increment missed_scans (source %q): %w", source, err)
		}
		if _, err := demote.Exec(source, uninstallConfirmThreshold); err != nil {
			return fmt.Errorf("mark uninstalled (source %q): %w", source, err)
		}
	}
	return nil
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
