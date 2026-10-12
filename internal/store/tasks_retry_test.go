package store

import (
	"testing"

	"sentinelgo/internal/taskstore"
)

// TestRetryOnFailure covers contract §4: retry_on_failure:false keeps a
// failed task failed; a missing key, true, or a malformed payload retries.
func TestRetryOnFailure(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantRetry bool
	}{
		{"false", `{"retry_on_failure":false,"timeout_minutes":60}`, false},
		{"true", `{"retry_on_failure":true}`, true},
		{"missing", `{"timeout_minutes":60}`, true},
		{"null payload", `null`, true},
		{"string false is not the boolean", `{"retry_on_failure":"false"}`, true},
		{"malformed payload", `{not json`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTaskStoreForTest(t)
			seedTask(t, ts, "t", "assigned")
			if _, err := ts.db.Exec(
				"UPDATE tasks SET status='failed', completed_at='2020-01-01T00:00:00Z', is_synced=1, payload=? WHERE id='t'",
				tt.payload); err != nil {
				t.Fatalf("setup: %v", err)
			}

			got, err := ts.GetRetryableTasks(0)
			if err != nil {
				t.Fatalf("GetRetryableTasks: %v", err)
			}
			if (len(got) == 1) != tt.wantRetry {
				t.Errorf("GetRetryableTasks returned %d tasks, want retry=%v", len(got), tt.wantRetry)
			}

			n, err := ts.ResetOldFailedTasks(0)
			if err != nil {
				t.Fatalf("ResetOldFailedTasks: %v", err)
			}
			wantStatus := "failed"
			if tt.wantRetry {
				wantStatus = "assigned"
			}
			if status := queryStatus(t, ts, "t"); (n == 1) != tt.wantRetry || status != wantStatus {
				t.Errorf("reset %d rows, status %q; want status %q", n, status, wantStatus)
			}
		})
	}
}

// TestRetryOnFailure_FromStoredTask stores a task the way polling does, so the
// filter reads the payload JSON that StoreTasks actually writes.
func TestRetryOnFailure_FromStoredTask(t *testing.T) {
	ts := newTaskStoreForTest(t)
	tasks := []taskstore.Task{{ID: "install", Status: "assigned", Payload: map[string]interface{}{"retry_on_failure": false}}}
	if err := ts.StoreTasks(tasks); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}
	if err := ts.UpdateTaskStatus("install", "failed", "boom", true); err != nil {
		t.Fatalf("UpdateTaskStatus: %v", err)
	}
	if _, err := ts.db.Exec("UPDATE tasks SET completed_at='2020-01-01T00:00:00Z' WHERE id='install'"); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if n, err := ts.ResetOldFailedTasks(0); err != nil || n != 0 {
		t.Fatalf("ResetOldFailedTasks = %d, %v; want 0 rows", n, err)
	}
	if status := queryStatus(t, ts, "install"); status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
}

// TestRetry_UnsyncedFailureNotReset: a failure recorded while offline must
// reach the server before the task is retried, or its status, note and
// result are lost (SyncPendingTasks only sends completed rows).
func TestRetry_UnsyncedFailureNotReset(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "t", "assigned")
	if err := ts.UpdateTaskResult("t", "failed", "exit 3", map[string]interface{}{"exit_code": 3}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.db.Exec("UPDATE tasks SET completed_at='2020-01-01T00:00:00Z' WHERE id='t'"); err != nil {
		t.Fatal(err)
	}

	if got, err := ts.GetRetryableTasks(0); err != nil || len(got) != 0 {
		t.Fatalf("GetRetryableTasks = %v, %v; want none while unsynced", got, err)
	}
	if n, err := ts.ResetOldFailedTasks(0); err != nil || n != 0 {
		t.Fatalf("ResetOldFailedTasks = %d, %v; want 0 while unsynced", n, err)
	}
	unsynced, err := ts.GetUnsyncedTasks()
	if err != nil || len(unsynced) != 1 || unsynced[0].Status != "failed" || unsynced[0].Result["exit_code"] != float64(3) {
		t.Fatalf("GetUnsyncedTasks = %+v, %v; want the failure with its result", unsynced, err)
	}

	if err := ts.MarkTaskSynced("t"); err != nil {
		t.Fatal(err)
	}
	if n, err := ts.ResetOldFailedTasks(0); err != nil || n != 1 {
		t.Fatalf("ResetOldFailedTasks after sync = %d, %v; want 1", n, err)
	}
}
