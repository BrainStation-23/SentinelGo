package store

import (
	"path/filepath"
	"testing"

	"sentinelgo/internal/taskstore"
)

func TestTaskCommandKind_RoundTrip(t *testing.T) {
	ts := newTaskStoreForTest(t)
	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "system", Status: "assigned", CommandKind: taskstore.CommandKindSystem},
		{ID: "unknown", Status: "assigned"},
	}); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}

	got, err := ts.GetAssignedTasks()
	if err != nil {
		t.Fatalf("GetAssignedTasks: %v", err)
	}
	byID := map[string]string{}
	for _, tk := range got {
		byID[tk.ID] = tk.CommandKind
	}
	if byID["system"] != taskstore.CommandKindSystem || byID["unknown"] != "" {
		t.Errorf("command kinds = %v, want system=%q unknown=\"\"", byID, taskstore.CommandKindSystem)
	}

	// The kind must also survive into the unsynced-results query.
	if err := ts.UpdateTaskStatus("system", "success", "done", false); err != nil {
		t.Fatalf("UpdateTaskStatus: %v", err)
	}
	unsynced, err := ts.GetUnsyncedTasks()
	if err != nil || len(unsynced) != 1 || unsynced[0].CommandKind != taskstore.CommandKindSystem {
		t.Errorf("GetUnsyncedTasks = %+v, %v; want the system task with its kind", unsynced, err)
	}
}

// TestTaskCommandKind_MigrationV6KeepsOldRows opens a v5 database: its tasks
// still load, with an unknown kind.
func TestTaskCommandKind_MigrationV6KeepsOldRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := Migrate(db, tasksMigrations[:5]); err != nil {
		t.Fatalf("Migrate to v5: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tasks (id, command_id, slug, name, description, category, tags, payload, scripts, status, note, created_by)
		VALUES ('old', 'c', 's', 'n', '', '', '[]', '{}', '{}', 'assigned', '', '')`); err != nil {
		t.Fatalf("insert v5 row: %v", err)
	}
	_ = db.Close()

	ts, err := NewTaskStore(path)
	if err != nil {
		t.Fatalf("NewTaskStore (migrate from v5): %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	if v, _ := CurrentVersion(ts.db); v != 6 {
		t.Errorf("schema version = %d, want 6", v)
	}
	got, err := ts.GetAssignedTasks()
	if err != nil || len(got) != 1 || got[0].ID != "old" || got[0].CommandKind != "" {
		t.Fatalf("GetAssignedTasks = %+v, %v; want the old task with an unknown kind", got, err)
	}
}
