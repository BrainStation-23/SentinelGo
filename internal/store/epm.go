package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/epm"
)

// EPMDBName is the filename of the local EPM policy/audit cache, placed
// alongside config.json. Kept in its own database file, separate from the
// software/services/task stores, so EPM schema changes never touch them.
const EPMDBName = "sentinelgo_epm.db"

const epmSchemaV1 = `
CREATE TABLE IF NOT EXISTS epm_policies (
	id         TEXT    PRIMARY KEY,
	app_path   TEXT    NOT NULL DEFAULT '',
	app_hash   TEXT    NOT NULL DEFAULT '',
	publisher  TEXT    NOT NULL DEFAULT '',
	user_id    TEXT    NOT NULL DEFAULT '',
	decision   TEXT    NOT NULL,
	expires_at TEXT    NOT NULL DEFAULT '',
	priority   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT    NOT NULL,
	updated_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_epm_policies_user ON epm_policies(user_id);

CREATE TABLE IF NOT EXISTS epm_audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	request_id  TEXT    NOT NULL,
	user_id     TEXT    NOT NULL,
	app_path    TEXT    NOT NULL DEFAULT '',
	app_hash    TEXT    NOT NULL DEFAULT '',
	decision    TEXT    NOT NULL,
	policy_id   TEXT    NOT NULL DEFAULT '',
	launched_at TEXT    NOT NULL,
	synced      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_epm_audit_request ON epm_audit_log(request_id);
CREATE INDEX        IF NOT EXISTS idx_epm_audit_synced  ON epm_audit_log(synced);
`

var epmMigrations = []Migration{
	{Version: 1, SQL: epmSchemaV1},
}

// EPMStore is a SQLite-backed local cache for EPM policy rules and the
// durable elevation-audit queue. It implements epm.AuditSink.
type EPMStore struct {
	db *sql.DB
}

// EPMAuditRow pairs a DB row ID with the reconstructed AuditEntry, mirroring
// store.PendingRow's role for the audit-log queue.
type EPMAuditRow struct {
	ID    int64
	Entry epm.AuditEntry
}

// NewEPMStore opens (or creates) the SQLite database at dbPath and applies
// schema migrations. The caller is responsible for closing the store.
func NewEPMStore(dbPath string) (*EPMStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open epm store: %w", err)
	}

	if err := Migrate(db, epmMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate epm store: %w", err)
	}

	return &EPMStore{db: db}, nil
}

// UpsertRules inserts or updates policy rules keyed by rule ID. created_at is
// preserved on update (it is only ever set on INSERT), so the original sync
// time is never overwritten by a later resync of the same rule.
func (s *EPMStore) UpsertRules(rules []epm.PolicyRule) error {
	if len(rules) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin upsert rules tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("EPMStore: rollback: %v", err)
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)

	stmt, err := tx.Prepare(`
		INSERT INTO epm_policies
			(id, app_path, app_hash, publisher, user_id, decision, expires_at, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			app_path   = excluded.app_path,
			app_hash   = excluded.app_hash,
			publisher  = excluded.publisher,
			user_id    = excluded.user_id,
			decision   = excluded.decision,
			expires_at = excluded.expires_at,
			priority   = excluded.priority,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare upsert rules stmt: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("EPMStore: close stmt: %v", err)
		}
	}()

	for _, rule := range rules {
		if _, err := stmt.Exec(
			rule.ID, rule.AppPath, rule.AppHash, rule.Publisher, rule.UserID,
			string(rule.Decision), formatExpiresAt(rule.ExpiresAt), rule.Priority,
			now, now,
		); err != nil {
			return fmt.Errorf("upsert rule %q: %w", rule.ID, err)
		}
	}

	return tx.Commit()
}

// DeleteRulesNotIn removes policy rules whose ID is not in activeIDs. Pass an
// empty slice to wipe every rule (a full sync that delivered zero rules).
// Callers must only invoke this after a complete rule-set sync, never after a
// partial one, or live rules would be dropped.
func (s *EPMStore) DeleteRulesNotIn(activeIDs []string) error {
	if len(activeIDs) == 0 {
		_, err := s.db.Exec("DELETE FROM epm_policies")
		return err
	}

	placeholders := make([]string, len(activeIDs))
	args := make([]any, len(activeIDs))
	for i, id := range activeIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := "DELETE FROM epm_policies WHERE id NOT IN (" + strings.Join(placeholders, ",") + ")"
	_, err := s.db.Exec(query, args...)
	return err
}

// GetRules returns every policy rule currently cached locally.
func (s *EPMStore) GetRules() ([]epm.PolicyRule, error) {
	rows, err := s.db.Query(`
		SELECT id, app_path, app_hash, publisher, user_id, decision, expires_at, priority
		FROM epm_policies
	`)
	if err != nil {
		return nil, fmt.Errorf("query epm policies: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("EPMStore: close rows: %v", err)
		}
	}()

	var rules []epm.PolicyRule
	for rows.Next() {
		var rule epm.PolicyRule
		var decision, expiresAt string
		if err := rows.Scan(
			&rule.ID, &rule.AppPath, &rule.AppHash, &rule.Publisher, &rule.UserID,
			&decision, &expiresAt, &rule.Priority,
		); err != nil {
			return nil, fmt.Errorf("scan epm policy: %w", err)
		}
		rule.Decision = epm.PolicyDecision(decision)
		rule.ExpiresAt = parseExpiresAt(expiresAt)
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// InsertAuditLog writes entry to the audit queue. A duplicate RequestID
// (retried sync) is silently ignored, satisfying epm.AuditSink.
func (s *EPMStore) InsertAuditLog(entry epm.AuditEntry) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO epm_audit_log
			(request_id, user_id, app_path, app_hash, decision, policy_id, launched_at, synced)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`,
		entry.RequestID, entry.UserID, entry.AppPath, entry.AppHash,
		string(entry.Decision), entry.PolicyID, entry.LaunchedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert epm audit log: %w", err)
	}
	return nil
}

// GetUnsyncedAuditLogs returns up to limit audit rows not yet uploaded.
// Pass limit <= 0 to retrieve all unsynced rows.
func (s *EPMStore) GetUnsyncedAuditLogs(limit int) ([]EPMAuditRow, error) {
	query := `
		SELECT id, request_id, user_id, app_path, app_hash, decision, policy_id, launched_at
		FROM epm_audit_log
		WHERE synced = 0
		ORDER BY id ASC
	`
	args := []any{}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query unsynced epm audit logs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("EPMStore: close rows: %v", err)
		}
	}()

	var result []EPMAuditRow
	for rows.Next() {
		var row EPMAuditRow
		var decision, launchedAt string
		if err := rows.Scan(
			&row.ID, &row.Entry.RequestID, &row.Entry.UserID, &row.Entry.AppPath,
			&row.Entry.AppHash, &decision, &row.Entry.PolicyID, &launchedAt,
		); err != nil {
			return nil, fmt.Errorf("scan epm audit log row: %w", err)
		}
		row.Entry.Decision = epm.PolicyDecision(decision)
		if t, err := time.Parse(time.RFC3339, launchedAt); err == nil {
			row.Entry.LaunchedAt = t
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// MarkAuditLogSynced flags the given audit-log row IDs as uploaded.
func (s *EPMStore) MarkAuditLogSynced(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	// #nosec G202 - placeholders is safely generated from strings.Repeat with only "?" and "," characters
	query := "UPDATE epm_audit_log SET synced = 1 WHERE id IN (" + placeholders + ")"

	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("mark epm audit logs synced: %w", err)
	}
	return nil
}

// Close releases the database connection.
func (s *EPMStore) Close() error {
	return s.db.Close()
}

func formatExpiresAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseExpiresAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
