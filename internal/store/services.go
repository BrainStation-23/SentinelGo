package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

const servicesSchemaV1 = `
CREATE TABLE IF NOT EXISTS services (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	agent_id     TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	display_name TEXT    NOT NULL DEFAULT '',
	status       TEXT    NOT NULL DEFAULT '',
	start_type   TEXT    NOT NULL DEFAULT '',
	description  TEXT    NOT NULL DEFAULT '',
	source       TEXT    NOT NULL DEFAULT '',
	pid          INTEGER NOT NULL DEFAULT 0,
	run_as       TEXT    NOT NULL DEFAULT '',
	first_seen_at TEXT   NOT NULL DEFAULT '',
	updated_at    TEXT   NOT NULL DEFAULT '',
	UNIQUE(agent_id, name, source)
);
CREATE INDEX IF NOT EXISTS idx_services_agent ON services(agent_id);
`

var servicesMigrations = []Migration{
	{Version: 1, SQL: servicesSchemaV1},
}

// ServicesStore is a SQLite-backed local cache for OS service state.
type ServicesStore struct {
	db *sql.DB
}

// NewServicesStore opens (or creates) the SQLite database at dbPath and applies
// schema migrations. The caller is responsible for closing the store.
func NewServicesStore(dbPath string) (*ServicesStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open services store: %w", err)
	}

	if err := Migrate(db, servicesMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate services store: %w", err)
	}

	return &ServicesStore{db: db}, nil
}

// Upsert inserts or updates services for agentID. first_seen_at is preserved
// on update so the original discovery timestamp is never overwritten.
func (s *ServicesStore) Upsert(agentID string, svcs []models.ServiceInfo) error {
	if len(svcs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin upsert tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("ServicesStore: rollback: %v", err)
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)

	stmt, err := tx.Prepare(`
		INSERT INTO services
			(agent_id, name, display_name, status, start_type, description, source, pid, run_as, first_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, name, source) DO UPDATE SET
			display_name  = excluded.display_name,
			status        = excluded.status,
			start_type    = excluded.start_type,
			description   = excluded.description,
			pid           = excluded.pid,
			run_as        = excluded.run_as,
			updated_at    = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare upsert stmt: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("ServicesStore: close stmt: %v", err)
		}
	}()

	for _, svc := range svcs {
		firstSeen := svc.FirstSeenAt
		if firstSeen == "" {
			firstSeen = now
		}
		updatedAt := svc.UpdatedAt
		if updatedAt == "" {
			updatedAt = now
		}
		_, err := stmt.Exec(
			agentID, svc.Name, svc.DisplayName, svc.Status, svc.StartType,
			svc.Description, svc.Source, svc.PID, svc.RunAs, firstSeen, updatedAt,
		)
		if err != nil {
			return fmt.Errorf("upsert service %q: %w", svc.Name, err)
		}
	}

	return tx.Commit()
}

// GetAll returns all services stored for agentID.
func (s *ServicesStore) GetAll(agentID string) ([]models.ServiceInfo, error) {
	rows, err := s.db.Query(`
		SELECT name, display_name, status, start_type, description, source, pid, run_as, first_seen_at, updated_at
		FROM services
		WHERE agent_id = ?
		ORDER BY source, name
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("ServicesStore: close rows: %v", err)
		}
	}()

	var svcs []models.ServiceInfo
	for rows.Next() {
		var svc models.ServiceInfo
		if err := rows.Scan(
			&svc.Name, &svc.DisplayName, &svc.Status, &svc.StartType,
			&svc.Description, &svc.Source, &svc.PID, &svc.RunAs,
			&svc.FirstSeenAt, &svc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		svcs = append(svcs, svc)
	}
	return svcs, rows.Err()
}

// DeleteNotIn removes services for agentID whose (name, source) key is not in
// activeKeys. activeKeys entries are "<name>\x00<source>". This prunes stale
// entries after a full scan.
func (s *ServicesStore) DeleteNotIn(agentID string, activeKeys []string) error {
	if len(activeKeys) == 0 {
		_, err := s.db.Exec("DELETE FROM services WHERE agent_id = ?", agentID)
		return err
	}

	// Build parameterised IN clause.
	placeholders := make([]string, len(activeKeys))
	args := make([]any, 0, len(activeKeys)+1)
	args = append(args, agentID)
	for i, k := range activeKeys {
		placeholders[i] = "?"
		args = append(args, k)
	}

	query := fmt.Sprintf(
		"DELETE FROM services WHERE agent_id = ? AND (name || char(0) || source) NOT IN (%s)",
		strings.Join(placeholders, ","),
	)
	_, err := s.db.Exec(query, args...)
	return err
}

// Close releases the database connection.
func (s *ServicesStore) Close() error {
	return s.db.Close()
}
