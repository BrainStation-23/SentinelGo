package store

import (
	"path/filepath"
	"reflect"
	"testing"

	"sentinelgo/internal/artifact"
	"sentinelgo/internal/taskstore"
)

func TestTaskArtifacts_RoundTrip(t *testing.T) {
	ts := newTaskStoreForTest(t)
	specs := []artifact.Spec{{
		ID:       "installer",
		Bucket:   "app-installers",
		Path:     "artifacts/7f3c/ZoomInstallerFull.msi",
		Filename: "ZoomInstallerFull.msi",
		SHA256:   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Size:     104857600,
	}}
	if err := ts.StoreTasks([]taskstore.Task{
		{ID: "with", Status: "assigned", Artifacts: specs},
		{ID: "without", Status: "assigned"},
	}); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}

	got, err := ts.GetAssignedTasks()
	if err != nil {
		t.Fatalf("GetAssignedTasks: %v", err)
	}
	byID := map[string]taskstore.Task{}
	for _, tk := range got {
		byID[tk.ID] = tk
	}
	if !reflect.DeepEqual(byID["with"].Artifacts, specs) {
		t.Errorf("artifacts = %+v, want %+v", byID["with"].Artifacts, specs)
	}
	if byID["without"].Artifacts != nil {
		t.Errorf("artifacts = %+v, want nil", byID["without"].Artifacts)
	}
	var raw *string
	if err := ts.db.QueryRow("SELECT artifacts FROM tasks WHERE id='without'").Scan(&raw); err != nil || raw != nil {
		t.Errorf("artifacts column = %v, %v; want NULL for a task without artifacts", raw, err)
	}
}

// TestTaskArtifacts_MigrationV4KeepsOldRows opens a database written before
// the artifacts column existed: its tasks still load, with no artifacts.
func TestTaskArtifacts_MigrationV4KeepsOldRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := Migrate(db, tasksMigrations[:3]); err != nil {
		t.Fatalf("Migrate to v3: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tasks (id, command_id, slug, name, description, category, tags, payload, scripts, status, note, created_by)
		VALUES ('old', 'c', 's', 'n', '', '', '[]', '{}', '{}', 'assigned', '', '')`); err != nil {
		t.Fatalf("insert v3 row: %v", err)
	}
	_ = db.Close()

	ts, err := NewTaskStore(path)
	if err != nil {
		t.Fatalf("NewTaskStore (migrate from v3): %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	if v, _ := CurrentVersion(ts.db); v != len(tasksMigrations) {
		t.Errorf("schema version = %d, want %d", v, len(tasksMigrations))
	}
	got, err := ts.GetAssignedTasks()
	if err != nil || len(got) != 1 || got[0].ID != "old" || got[0].Artifacts != nil {
		t.Fatalf("GetAssignedTasks = %+v, %v; want the old task with no artifacts", got, err)
	}
}

// TestTaskArtifacts_Unreadable: a corrupt artifacts column must not load as
// "no artifacts", or the script would run without its files.
func TestTaskArtifacts_Unreadable(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "bad", "assigned")
	if _, err := ts.db.Exec("UPDATE tasks SET artifacts='{not json' WHERE id='bad'"); err != nil {
		t.Fatal(err)
	}
	got, err := ts.GetAssignedTasks()
	if err != nil || len(got) != 1 {
		t.Fatalf("GetAssignedTasks = %v, %v", got, err)
	}
	if len(got[0].Artifacts) == 0 {
		t.Fatal("unreadable artifacts loaded as none")
	}
	if artifact.Validate(got[0].Artifacts) == nil {
		t.Error("the placeholder for unreadable artifacts passes validation")
	}
}
