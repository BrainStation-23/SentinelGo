package store

import (
	"database/sql"
	"fmt"
)

// Migration describes a single, versioned schema change.
type Migration struct {
	Version int
	SQL     string
}

// CurrentVersion returns the schema version stored in the database.
// Returns 0 if the schema_version table does not exist or is empty.
func CurrentVersion(db *sql.DB) (int, error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return 0, fmt.Errorf("ensure schema_version table: %w", err)
	}

	var v int
	err := db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read schema_version: %w", err)
	}
	return v, nil
}

// Migrate applies every migration whose Version is greater than the current schema version,
// in ascending order, each in its own transaction. The schema_version row is updated atomically
// with the migration SQL so a crash mid-migration leaves the version un-bumped and the
// migration will retry on the next startup.
func Migrate(db *sql.DB, migrations []Migration) error {
	current, err := CurrentVersion(db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", m.Version, err)
		}

		if _, err := tx.Exec(m.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration v%d: %w", m.Version, err)
		}

		if current == 0 {
			if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", m.Version); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("record migration v%d: %w", m.Version, err)
			}
		} else {
			if _, err := tx.Exec("UPDATE schema_version SET version = ?", m.Version); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("record migration v%d: %w", m.Version, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", m.Version, err)
		}

		current = m.Version
	}

	return nil
}
