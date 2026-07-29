package store

import (
	"database/sql"
	"errors"
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

// epmSchemaV2 adds script/installer-elevation and service-scoped-elevation
// columns to the existing tables. ALTER TABLE ADD COLUMN is
// backward-compatible: existing rows receive the DEFAULT value so no data
// migration is required.
const epmSchemaV2 = `
ALTER TABLE epm_policies  ADD COLUMN script_hash          TEXT NOT NULL DEFAULT '';
ALTER TABLE epm_policies  ADD COLUMN allowed_args         TEXT NOT NULL DEFAULT '';
ALTER TABLE epm_policies  ADD COLUMN allowed_service_name TEXT NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN script_hash          TEXT NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN service_name         TEXT NOT NULL DEFAULT '';
`

// epmMigrations is append-only: v1 and v2's SQL below is never edited once
// released (an already-migrated agent never re-runs it), and new versions are
// only ever added at the end, in ascending order — store.Migrate applies
// migrations in the order given, not sorted. v3 onward lives in
// schema_epm_v3.go, for the v2 policy engine (internal/epm's Phase 1
// condition-tree rule model).
var epmMigrations = append([]Migration{
	{Version: 1, SQL: epmSchemaV1},
	{Version: 2, SQL: epmSchemaV2},
}, epmMigrationsV3Plus...)

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
			(id, app_path, app_hash, publisher, user_id, decision, expires_at, priority,
			 script_hash, allowed_args, allowed_service_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			app_path              = excluded.app_path,
			app_hash              = excluded.app_hash,
			publisher             = excluded.publisher,
			user_id               = excluded.user_id,
			decision              = excluded.decision,
			expires_at            = excluded.expires_at,
			priority              = excluded.priority,
			script_hash           = excluded.script_hash,
			allowed_args          = excluded.allowed_args,
			allowed_service_name  = excluded.allowed_service_name,
			updated_at            = excluded.updated_at
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
			rule.ScriptHash, rule.AllowedArgs, rule.AllowedServiceName,
			now, now,
		); err != nil {
			return fmt.Errorf("upsert rule %q: %w", rule.ID, err)
		}
	}

	return tx.Commit()
}

// ErrEmptyActiveIDs is returned by DeleteRulesNotIn when activeIDs is empty.
// See DeleteRulesNotIn for why an empty set is not silently treated as "the
// server sent zero rules".
var ErrEmptyActiveIDs = errors.New("DeleteRulesNotIn: empty ID set; call PruneAll explicitly to wipe all rules")

// PruneAll removes every cached policy rule. It is split out from
// DeleteRulesNotIn so that a nil or empty ID slice — which a malformed,
// truncated, or partially-parsed sync payload can trivially produce — can never
// be mistaken for a deliberate "the server sent zero rules" instruction.
//
// Wiping the cache is not a benign operation: policy evaluation is default-deny
// (see epm.Engine.Evaluate), so an empty rule set locks every user out of every
// elevation until the next successful sync. Only call this when the server has
// explicitly delivered an empty rule set.
func (s *EPMStore) PruneAll() error {
	if _, err := s.db.Exec("DELETE FROM epm_policies"); err != nil {
		return fmt.Errorf("prune all epm policies: %w", err)
	}
	return nil
}

// DeleteRulesNotIn removes policy rules whose ID is not in activeIDs. Callers
// must only invoke this after a complete rule-set sync, never after a partial
// one, or live rules would be dropped.
//
// An empty activeIDs returns ErrEmptyActiveIDs rather than deleting everything:
// see PruneAll for the rationale.
func (s *EPMStore) DeleteRulesNotIn(activeIDs []string) error {
	if len(activeIDs) == 0 {
		return ErrEmptyActiveIDs
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

// GetRules returns every policy rule currently cached locally, ordered by rule
// ID.
//
// The ORDER BY is load-bearing, not cosmetic: SQLite makes no guarantee about
// the row order of an unordered scan, and epm.Engine.Evaluate breaks ties
// between rules of equal (tier, priority) by which it saw first. Without a
// stable order, two such rules produce a nondeterministic verdict across agent
// restarts — the same request allowed on one boot and denied on the next.
func (s *EPMStore) GetRules() ([]epm.PolicyRule, error) {
	rows, err := s.db.Query(`
		SELECT id, app_path, app_hash, publisher, user_id, decision, expires_at, priority,
		       script_hash, allowed_args, allowed_service_name
		FROM epm_policies
		ORDER BY id ASC
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
			&rule.ScriptHash, &rule.AllowedArgs, &rule.AllowedServiceName,
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
// (retried sync) is silently ignored, satisfying epm.AuditSink. The Phase 8
// enrichment columns (verdict, mode, bundle_id, ...) all have SQL DEFAULTs
// (see epmSchemaV5), so a caller passing a v1-shaped AuditEntry with those
// fields at their zero value writes exactly the same row shape as before
// Phase 8 existed — this INSERT statement is a strict superset of the
// pre-Phase-8 one, not a replacement.
func (s *EPMStore) InsertAuditLog(entry epm.AuditEntry) error {
	var retainUntil string
	if entry.RetainUntil != nil {
		retainUntil = entry.RetainUntil.UTC().Format(time.RFC3339)
	}
	// exit_code's SQL DEFAULT is -1 ("unknown"); entry.ExitCode is a
	// pointer specifically so nil (unknown) is never confused with a real
	// exit code of 0 (success) — see AuditEntry.ExitCode's doc comment.
	exitCode := -1
	if entry.ExitCode != nil {
		exitCode = *entry.ExitCode
	}

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO epm_audit_log
			(request_id, user_id, app_path, app_hash, decision, policy_id, launched_at,
			 script_hash, service_name, synced,
			 verdict, mode, bundle_id, rule_version, specificity, publisher, command_line,
			 process_id, parent_pid, parent_path, exit_code, justification, approval_id,
			 grant_id, device_context, matched_conditions, agent_version, retain_until)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		entry.RequestID, entry.UserID, entry.AppPath, entry.AppHash,
		string(entry.Decision), entry.PolicyID, entry.LaunchedAt.UTC().Format(time.RFC3339),
		entry.ScriptHash, entry.ServiceName,
		string(entry.Verdict), string(entry.Mode), entry.BundleID, entry.RuleVersion, entry.Specificity,
		entry.Publisher, entry.CommandLine,
		entry.ProcessID, entry.ParentPID, entry.ParentPath, exitCode, entry.Justification,
		entry.ApprovalID, entry.GrantID, entry.DeviceContext, entry.MatchedConditions,
		entry.AgentVersion, retainUntil,
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
		SELECT id, request_id, user_id, app_path, app_hash, decision, policy_id, launched_at,
		       script_hash, service_name,
		       verdict, mode, bundle_id, rule_version, specificity, publisher, command_line,
		       process_id, parent_pid, parent_path, exit_code, justification, approval_id,
		       grant_id, device_context, matched_conditions, agent_version, retain_until
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
		var decision, launchedAt, verdict, mode, retainUntil string
		var exitCode int
		if err := rows.Scan(
			&row.ID, &row.Entry.RequestID, &row.Entry.UserID, &row.Entry.AppPath,
			&row.Entry.AppHash, &decision, &row.Entry.PolicyID, &launchedAt,
			&row.Entry.ScriptHash, &row.Entry.ServiceName,
			&verdict, &mode, &row.Entry.BundleID, &row.Entry.RuleVersion, &row.Entry.Specificity,
			&row.Entry.Publisher, &row.Entry.CommandLine,
			&row.Entry.ProcessID, &row.Entry.ParentPID, &row.Entry.ParentPath, &exitCode, &row.Entry.Justification,
			&row.Entry.ApprovalID, &row.Entry.GrantID, &row.Entry.DeviceContext, &row.Entry.MatchedConditions,
			&row.Entry.AgentVersion, &retainUntil,
		); err != nil {
			return nil, fmt.Errorf("scan epm audit log row: %w", err)
		}
		row.Entry.Decision = epm.PolicyDecision(decision)
		row.Entry.Verdict = epm.Verdict(verdict)
		row.Entry.Mode = epm.ElevationMode(mode)
		if exitCode != -1 {
			row.Entry.ExitCode = &exitCode
		}
		if retainUntil != "" {
			if t, err := time.Parse(time.RFC3339, retainUntil); err == nil {
				row.Entry.RetainUntil = &t
			}
		}
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

// PruneAuditLog deletes already-uploaded (synced=1) audit rows older than
// cutoff — closes audit finding DB-3 (see epm-db-maintenance in
// main_integration.go): rows were flagged synced=1 and never deleted,
// growing the local SQLite file unboundedly on a long-running agent.
// Unsynced rows are never touched regardless of age — a row not yet
// uploaded is not eligible for deletion no matter how old, since deleting
// it would silently lose that elevation from the audit trail forever.
func (s *EPMStore) PruneAuditLog(cutoff time.Time) error {
	_, err := s.db.Exec(
		`DELETE FROM epm_audit_log WHERE synced = 1 AND launched_at < ?`,
		cutoff.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("prune epm audit log: %w", err)
	}
	return nil
}

// PruneProcessEvents deletes already-uploaded (synced=1) rows from
// epm_process_events (Phase 6's procmon telemetry) older than cutoff — the
// same fail-safe as PruneAuditLog, for the same reason.
func (s *EPMStore) PruneProcessEvents(cutoff time.Time) error {
	_, err := s.db.Exec(
		`DELETE FROM epm_process_events WHERE synced = 1 AND observed_at < ?`,
		cutoff.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("prune epm process events: %w", err)
	}
	return nil
}

// Vacuum reclaims disk space freed by PruneAuditLog/PruneProcessEvents/
// PruneBundles. SQLite does not shrink the on-disk file on DELETE by
// itself; VACUUM is the only way to actually give that space back to the
// filesystem. Called occasionally (see epm-db-maintenance), not after every
// prune — VACUUM rewrites the entire database file, which is wasteful to
// do on every weekly maintenance cycle if there was little to reclaim.
func (s *EPMStore) Vacuum() error {
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("vacuum epm database: %w", err)
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
