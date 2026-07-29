package store

// epmMigrationsV3Plus extends epmMigrations (epm.go) with the schema for the
// v2 policy engine (internal/epm's Phase 1 condition-tree rule model): signed
// policy bundles, condition-tree rules and rule groups, elevation grants and
// approval requests, and audit enrichment.
//
// Append-only, same as epmMigrations itself: v1 and v2's SQL is never edited,
// and neither is v3/v4/v5's once released — store.Migrate applies whichever
// migrations have Version > the database's current version, so a downgraded
// binary simply stops applying migrations it doesn't recognize rather than
// corrupting a newer database, and a fresh v1-era database upgrades through
// all five in one Migrate call.
//
// Split into three migrations rather than one large one so a failure retries
// the smallest unit that actually failed, matching the granularity epmSchemaV1
// (tables) / epmSchemaV2 (columns) already established.
var epmMigrationsV3Plus = []Migration{
	{Version: 3, SQL: epmSchemaV3},
	{Version: 4, SQL: epmSchemaV4},
	{Version: 5, SQL: epmSchemaV5},
}

// epmSchemaV3 adds signed policy bundles and the v2 condition-tree rule
// representation (internal/epm.RuleV2 / RuleGroup, JSON-serialized). The
// epm_policies table (v1/v2) is untouched and remains authoritative for any
// backend still sending the v1 rule payload shape — see
// internal/service/task/native/epm_policy_sync.go; both write paths coexist
// during migration to v2-capable backends (Phase 3).
const epmSchemaV3 = `
CREATE TABLE IF NOT EXISTS epm_bundles (
	bundle_id      TEXT    PRIMARY KEY,
	generation     INTEGER NOT NULL,
	parent_id      TEXT    NOT NULL DEFAULT '',
	tenant_id      TEXT    NOT NULL DEFAULT '',
	mode           TEXT    NOT NULL DEFAULT 'full',
	schema_version INTEGER NOT NULL DEFAULT 2,
	issued_at      TEXT    NOT NULL,
	not_after      TEXT    NOT NULL DEFAULT '',
	key_id         TEXT    NOT NULL DEFAULT '',
	signature      TEXT    NOT NULL DEFAULT '',
	sig_status     TEXT    NOT NULL DEFAULT 'unverified',
	payload        BLOB    NOT NULL,
	received_at    TEXT    NOT NULL,
	applied_at     TEXT    NOT NULL DEFAULT '',
	state          TEXT    NOT NULL DEFAULT 'staged'
);
CREATE INDEX IF NOT EXISTS idx_epm_bundles_state ON epm_bundles(state);
CREATE INDEX IF NOT EXISTS idx_epm_bundles_gen   ON epm_bundles(generation);

CREATE TABLE IF NOT EXISTS epm_rules_v2 (
	bundle_id      TEXT    NOT NULL,
	id             TEXT    NOT NULL,
	group_id       TEXT    NOT NULL DEFAULT '',
	version        INTEGER NOT NULL DEFAULT 1,
	enabled        INTEGER NOT NULL DEFAULT 1,
	priority       INTEGER NOT NULL DEFAULT 0,
	conditions     TEXT    NOT NULL DEFAULT '',
	outcome        TEXT    NOT NULL,
	effective_from TEXT    NOT NULL DEFAULT '',
	expires_at     TEXT    NOT NULL DEFAULT '',
	on_unknown     TEXT    NOT NULL DEFAULT '',
	labels         TEXT    NOT NULL DEFAULT '',
	static_spec    INTEGER NOT NULL DEFAULT 0,
	created_at     TEXT    NOT NULL,
	updated_at     TEXT    NOT NULL,
	PRIMARY KEY (bundle_id, id)
);
CREATE INDEX IF NOT EXISTS idx_epm_rules_v2_bundle ON epm_rules_v2(bundle_id, enabled);

CREATE TABLE IF NOT EXISTS epm_rule_groups (
	bundle_id  TEXT    NOT NULL,
	id         TEXT    NOT NULL,
	name       TEXT    NOT NULL DEFAULT '',
	enabled    INTEGER NOT NULL DEFAULT 1,
	priority   INTEGER NOT NULL DEFAULT 0,
	conditions TEXT    NOT NULL DEFAULT '',
	defaults   TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY (bundle_id, id)
);
`

// epmSchemaV4 adds elevation grants (backing ModeRunOnce/ModeTemporary/
// ModeSession — see internal/epm's ElevationMode) and out-of-band approval
// requests (VerdictRequireApproval).
const epmSchemaV4 = `
CREATE TABLE IF NOT EXISTS epm_grants (
	grant_id   TEXT    PRIMARY KEY,
	rule_id    TEXT    NOT NULL,
	bundle_id  TEXT    NOT NULL DEFAULT '',
	user_id    TEXT    NOT NULL,
	mode       TEXT    NOT NULL,
	uses_count INTEGER NOT NULL DEFAULT 0,
	max_uses   INTEGER NOT NULL DEFAULT 0,
	issued_at  TEXT    NOT NULL,
	expires_at TEXT    NOT NULL DEFAULT '',
	session_id TEXT    NOT NULL DEFAULT '',
	revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_epm_grants_rule_user ON epm_grants(rule_id, user_id);
CREATE INDEX IF NOT EXISTS idx_epm_grants_expires   ON epm_grants(expires_at);

CREATE TABLE IF NOT EXISTS epm_approvals (
	approval_id   TEXT PRIMARY KEY,
	request_id    TEXT NOT NULL,
	rule_id       TEXT NOT NULL DEFAULT '',
	user_id       TEXT NOT NULL,
	app_path      TEXT NOT NULL DEFAULT '',
	justification TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL DEFAULT 'pending',
	requested_at  TEXT NOT NULL,
	resolved_at   TEXT NOT NULL DEFAULT '',
	resolved_by   TEXT NOT NULL DEFAULT '',
	expires_at    TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_epm_approvals_request ON epm_approvals(request_id);
CREATE INDEX        IF NOT EXISTS idx_epm_approvals_status  ON epm_approvals(status);
`

// epmSchemaV5 enriches the existing epm_audit_log table (every column is an
// ADD COLUMN with a DEFAULT, so existing rows and the current
// INSERT/SELECT in epm.go keep working untouched) and adds process telemetry
// (Phase 6's procmon). AuditEntry's own Go-side fields stay v1-shaped until
// Phase 8 actually populates these columns; the columns exist now so that
// phase is a pure application-logic change, not a further schema migration.
const epmSchemaV5 = `
ALTER TABLE epm_audit_log ADD COLUMN verdict            TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN mode               TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN bundle_id          TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN rule_version       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE epm_audit_log ADD COLUMN specificity        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE epm_audit_log ADD COLUMN publisher          TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN command_line       TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN process_id         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE epm_audit_log ADD COLUMN parent_pid         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE epm_audit_log ADD COLUMN parent_path        TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN exit_code          INTEGER NOT NULL DEFAULT -1;
ALTER TABLE epm_audit_log ADD COLUMN justification      TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN approval_id        TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN grant_id           TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN device_context     TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN matched_conditions TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN agent_version      TEXT    NOT NULL DEFAULT '';
ALTER TABLE epm_audit_log ADD COLUMN retain_until       TEXT    NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_epm_audit_retain ON epm_audit_log(synced, retain_until);

CREATE TABLE IF NOT EXISTS epm_process_events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at  TEXT    NOT NULL,
	kind         TEXT    NOT NULL,
	pid          INTEGER NOT NULL DEFAULT 0,
	parent_pid   INTEGER NOT NULL DEFAULT 0,
	session_id   INTEGER NOT NULL DEFAULT 0,
	user_id      TEXT    NOT NULL DEFAULT '',
	image_path   TEXT    NOT NULL DEFAULT '',
	command_line TEXT    NOT NULL DEFAULT '',
	exit_code    INTEGER NOT NULL DEFAULT -1,
	elevated     TEXT    NOT NULL DEFAULT '',
	source       TEXT    NOT NULL DEFAULT '',
	grant_id     TEXT    NOT NULL DEFAULT '',
	synced       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_epm_process_events_synced ON epm_process_events(synced);
CREATE INDEX IF NOT EXISTS idx_epm_process_events_pid    ON epm_process_events(pid);
`
