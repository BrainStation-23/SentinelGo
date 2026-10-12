package store

import "testing"

func TestTaskResult_StoredForUnsyncedAndClearedOnRetry(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "t", "assigned")

	result := map[string]interface{}{"exit_code": 3010, "reboot_required": true}
	if err := ts.UpdateTaskResult("t", "failed", "note", result, false); err != nil {
		t.Fatalf("UpdateTaskResult: %v", err)
	}
	unsynced, err := ts.GetUnsyncedTasks()
	if err != nil || len(unsynced) != 1 {
		t.Fatalf("GetUnsyncedTasks = %v, %v", unsynced, err)
	}
	got := unsynced[0].Result
	if got["exit_code"] != float64(3010) || got["reboot_required"] != true {
		t.Errorf("Result = %v", got)
	}

	// A retry starts clean: the next run reports its own result.
	if _, err := ts.db.Exec("UPDATE tasks SET completed_at='2020-01-01T00:00:00Z' WHERE id='t'"); err != nil {
		t.Fatal(err)
	}
	if n, err := ts.ResetOldFailedTasks(0); err != nil || n != 1 {
		t.Fatalf("ResetOldFailedTasks = %d, %v", n, err)
	}
	var raw *string
	if err := ts.db.QueryRow("SELECT result FROM tasks WHERE id='t'").Scan(&raw); err != nil || raw != nil {
		t.Errorf("result after reset = %v, %v; want NULL", raw, err)
	}
}

func TestTaskResult_UpdateTaskStatusClearsResult(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "t", "assigned")
	if err := ts.UpdateTaskResult("t", "failed", "n", map[string]interface{}{"exit_code": 1}, false); err != nil {
		t.Fatal(err)
	}
	if err := ts.UpdateTaskStatus("t", "retrying", "n", false); err != nil {
		t.Fatal(err)
	}
	unsynced, _ := ts.GetUnsyncedTasks()
	if len(unsynced) != 1 || unsynced[0].Result != nil {
		t.Errorf("Result = %v, want nil after a plain status update", unsynced)
	}
}
