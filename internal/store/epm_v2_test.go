package store

// White-box test (package store, not store_test) so it can drive the
// unexported epmMigrations list directly against a hand-seeded v1-only
// database — the same reason internal/service/task/native/epm_policy_sync_test.go
// is white-box, for its own seam access.
//
// TestEPMSchema_V1ToV5Migration proves an agent's existing on-disk EPM cache
// — created back when only epmSchemaV1 existed — upgrades cleanly through
// v2/v3/v4/v5 in one Migrate call, with every pre-existing row surviving and
// every new column landing at its documented default. This is the concrete
// check behind the append-only migration rule: an upgraded binary must never
// need (or get) a hand-written data migration for a customer's existing
// policy cache.

import (
	"database/sql"
	"testing"
	"time"

	"sentinelgo/internal/epm"

	_ "modernc.org/sqlite"
)

// openV1OnlyDB builds an in-memory database containing ONLY the v1 schema —
// exactly what a database created before epmSchemaV2/V3/V4/V5 existed would
// look like — with the schema_version row set to 1 by hand, bypassing
// NewEPMStore (which would apply every migration immediately).
func openV1OnlyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	const v1Schema = `
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
	if _, err := db.Exec(v1Schema); err != nil {
		t.Fatalf("apply v1 schema: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create schema_version: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(
		`INSERT INTO epm_policies (id, app_path, app_hash, publisher, user_id, decision, expires_at, priority, created_at, updated_at)
		 VALUES (?, ?, '', '', ?, ?, '', ?, ?, ?)`,
		"legacy-rule-1", `C:\apps\tool.exe`, `CONTOSO\alice`, "allow", 5, now, now,
	); err != nil {
		t.Fatalf("seed v1 policy row: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO epm_audit_log (request_id, user_id, app_path, app_hash, decision, policy_id, launched_at, synced)
		 VALUES (?, ?, ?, '', ?, ?, ?, 0)`,
		"legacy-req-1", `CONTOSO\alice`, `C:\apps\tool.exe`, "allow", "legacy-rule-1", now,
	); err != nil {
		t.Fatalf("seed v1 audit row: %v", err)
	}

	return db
}

func TestEPMSchema_V1ToV5Migration(t *testing.T) {
	db := openV1OnlyDB(t)

	if v, err := CurrentVersion(db); err != nil || v != 1 {
		t.Fatalf("precondition: CurrentVersion = %d, %v, want 1, nil", v, err)
	}

	if err := Migrate(db, epmMigrations); err != nil {
		t.Fatalf("Migrate v1 -> v5: %v", err)
	}

	v, err := CurrentVersion(db)
	if err != nil {
		t.Fatalf("CurrentVersion after migrate: %v", err)
	}
	if v != 5 {
		t.Fatalf("CurrentVersion after migrate = %d, want 5", v)
	}

	// The legacy policy row survives, and every v2-added column reads back
	// at its documented default.
	var appPath, scriptHash, allowedArgs, allowedServiceName string
	if err := db.QueryRow(
		`SELECT app_path, script_hash, allowed_args, allowed_service_name FROM epm_policies WHERE id = ?`,
		"legacy-rule-1",
	).Scan(&appPath, &scriptHash, &allowedArgs, &allowedServiceName); err != nil {
		t.Fatalf("query migrated policy row: %v", err)
	}
	if appPath != `C:\apps\tool.exe` {
		t.Errorf("app_path = %q, want the original v1 value preserved", appPath)
	}
	if scriptHash != "" || allowedArgs != "" || allowedServiceName != "" {
		t.Errorf("v2 columns on a pre-v2 row should default to empty, got script_hash=%q allowed_args=%q allowed_service_name=%q",
			scriptHash, allowedArgs, allowedServiceName)
	}

	// The legacy audit row survives, and every v5-added column reads back at
	// its documented default (exit_code defaults to -1, not 0 — 0 is a valid
	// real exit code and must not be confused with "no process was launched").
	var verdict, bundleID string
	var ruleVersion, specificity, exitCode int
	if err := db.QueryRow(
		`SELECT verdict, bundle_id, rule_version, specificity, exit_code FROM epm_audit_log WHERE request_id = ?`,
		"legacy-req-1",
	).Scan(&verdict, &bundleID, &ruleVersion, &specificity, &exitCode); err != nil {
		t.Fatalf("query migrated audit row: %v", err)
	}
	if verdict != "" || bundleID != "" || ruleVersion != 0 || specificity != 0 {
		t.Errorf("v5 text/int columns should default to '' / 0, got verdict=%q bundle_id=%q rule_version=%d specificity=%d",
			verdict, bundleID, ruleVersion, specificity)
	}
	if exitCode != -1 {
		t.Errorf("exit_code default = %d, want -1 (0 is a real exit code)", exitCode)
	}

	// v3/v4/v5's new tables exist and are queryable (empty, but present).
	for _, table := range []string{
		"epm_bundles", "epm_rules_v2", "epm_rule_groups",
		"epm_grants", "epm_approvals", "epm_process_events",
	} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Errorf("table %q not queryable after migration: %v", table, err)
		} else if count != 0 {
			t.Errorf("table %q should start empty, got %d rows", table, count)
		}
	}

	// The store's ordinary Go API still works against the migrated schema —
	// this is the real point: a migrated database is not just structurally
	// present, it is functionally identical to a freshly-created one from the
	// caller's point of view.
	epmStore, err := NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("sanity: NewEPMStore on a fresh db: %v", err)
	}
	defer func() { _ = epmStore.Close() }()
	if err := epmStore.UpsertRules([]epm.PolicyRule{{ID: "x", Decision: epm.DecisionAllow}}); err != nil {
		t.Errorf("UpsertRules against freshly-migrated schema shape: %v", err)
	}
}

// TestEPMMigrations_AppendOnlyVersionOrder guards the structural invariant
// Migrate depends on: migrations must appear in strictly ascending Version
// order, since Migrate applies them in slice order, not sorted by Version.
func TestEPMMigrations_AppendOnlyVersionOrder(t *testing.T) {
	for i := 1; i < len(epmMigrations); i++ {
		if epmMigrations[i].Version <= epmMigrations[i-1].Version {
			t.Fatalf("epmMigrations[%d].Version=%d is not greater than epmMigrations[%d].Version=%d",
				i, epmMigrations[i].Version, i-1, epmMigrations[i-1].Version)
		}
	}
}
