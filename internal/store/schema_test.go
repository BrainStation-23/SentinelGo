package store

import (
	"path/filepath"
	"testing"
)

func TestCurrentVersion_ZeroWhenNoTable(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "schema_fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	v, err := CurrentVersion(db)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 0 {
		t.Errorf("CurrentVersion() = %d, want 0", v)
	}
}

func TestCurrentVersion_MalformedRow(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "schema_malformed.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE TABLE schema_version (version TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES ('not-a-number')`); err != nil {
		t.Fatalf("insert malformed row: %v", err)
	}

	if _, err := CurrentVersion(db); err == nil {
		t.Fatal("expected an error scanning a non-integer schema_version row")
	}
}

func TestMigrate_AppliesInOrderAndSkipsAlreadyApplied(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "schema_migrate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	migrations := []Migration{
		{Version: 1, SQL: `CREATE TABLE items (id INTEGER PRIMARY KEY)`},
		{Version: 2, SQL: `ALTER TABLE items ADD COLUMN name TEXT`},
	}
	if err := Migrate(db, migrations); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	v, err := CurrentVersion(db)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 2 {
		t.Errorf("CurrentVersion() after migrate = %d, want 2", v)
	}

	if _, err := db.Exec(`INSERT INTO items (id, name) VALUES (1, 'x')`); err != nil {
		t.Errorf("migrated schema should accept inserts using the new column: %v", err)
	}

	// Re-running Migrate with the same set must be a no-op (no duplicate schema_version rows).
	if err := Migrate(db, migrations); err != nil {
		t.Fatalf("re-running Migrate: %v", err)
	}
	var rowCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&rowCount); err != nil {
		t.Fatalf("count schema_version rows: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("schema_version row count = %d, want 1 (UPDATE not INSERT on already-applied migrations)", rowCount)
	}
}

func TestMigrate_UpdatesVersionOnReopenedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema_reopen.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("Open (first): %v", err)
	}
	if err := Migrate(db1, []Migration{{Version: 1, SQL: `CREATE TABLE items (id INTEGER PRIMARY KEY)`}}); err != nil {
		t.Fatalf("Migrate v1: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("close first handle: %v", err)
	}

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("Open (second): %v", err)
	}
	defer func() { _ = db2.Close() }()

	// current > 0 here, so this exercises the UPDATE (not INSERT) branch of Migrate.
	if err := Migrate(db2, []Migration{
		{Version: 1, SQL: `CREATE TABLE items (id INTEGER PRIMARY KEY)`},
		{Version: 2, SQL: `ALTER TABLE items ADD COLUMN name TEXT`},
	}); err != nil {
		t.Fatalf("Migrate v2 on reopened db: %v", err)
	}

	v, err := CurrentVersion(db2)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 2 {
		t.Errorf("CurrentVersion() after reopen+migrate = %d, want 2", v)
	}

	var rowCount int
	if err := db2.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&rowCount); err != nil {
		t.Fatalf("count schema_version rows: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("schema_version row count = %d, want 1 (UPDATE must not insert a second row)", rowCount)
	}
}

func TestMigrate_InvalidSQLRollsBack(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "schema_bad_sql.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = Migrate(db, []Migration{{Version: 1, SQL: `NOT VALID SQL AT ALL`}})
	if err == nil {
		t.Fatal("expected an error for invalid migration SQL")
	}

	v, cerr := CurrentVersion(db)
	if cerr != nil {
		t.Fatalf("CurrentVersion: %v", cerr)
	}
	if v != 0 {
		t.Errorf("CurrentVersion() after failed migration = %d, want 0 (rolled back)", v)
	}
}
