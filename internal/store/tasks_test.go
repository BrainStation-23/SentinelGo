package store

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
)

func newTaskStoreForTest(t *testing.T) *TaskStore {
	t.Helper()
	ts, err := NewTaskStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatalf("NewTaskStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	return ts
}

func seedTask(t *testing.T, ts *TaskStore, id, status string) {
	t.Helper()
	tasks := []taskstore.Task{{ID: id, Name: "test task", Status: status}}
	if err := ts.StoreTasks(tasks); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}
}

func queryStatus(t *testing.T, ts *TaskStore, id string) string {
	t.Helper()
	var status string
	if err := ts.db.QueryRow("SELECT status FROM tasks WHERE id = ?", id).Scan(&status); err != nil {
		t.Fatalf("query status for %s: %v", id, err)
	}
	return status
}

func queryAttemptCount(t *testing.T, ts *TaskStore, id string) int {
	t.Helper()
	var n int
	if err := ts.db.QueryRow("SELECT attempt_count FROM tasks WHERE id = ?", id).Scan(&n); err != nil {
		t.Fatalf("query attempt_count for %s: %v", id, err)
	}
	return n
}

func queryIsSynced(t *testing.T, ts *TaskStore, id string) int {
	t.Helper()
	var n int
	if err := ts.db.QueryRow("SELECT is_synced FROM tasks WHERE id = ?", id).Scan(&n); err != nil {
		t.Fatalf("query is_synced for %s: %v", id, err)
	}
	return n
}

// TestMarkTaskExecuting confirms the status transitions from 'assigned' to 'executing'.
func TestMarkTaskExecuting(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-1", "assigned")

	if err := ts.MarkTaskExecuting("task-1"); err != nil {
		t.Fatalf("MarkTaskExecuting: %v", err)
	}

	if got := queryStatus(t, ts, "task-1"); got != "executing" {
		t.Errorf("status after MarkTaskExecuting = %q, want %q", got, "executing")
	}
}

// TestMarkTaskExecuting_NotPickedUpAgain confirms GetAssignedTasks skips 'executing' tasks.
func TestMarkTaskExecuting_NotPickedUpAgain(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-exec", "assigned")

	if err := ts.MarkTaskExecuting("task-exec"); err != nil {
		t.Fatalf("MarkTaskExecuting: %v", err)
	}

	tasks, err := ts.GetAssignedTasks()
	if err != nil {
		t.Fatalf("GetAssignedTasks: %v", err)
	}
	for _, task := range tasks {
		if task.ID == "task-exec" {
			t.Error("GetAssignedTasks returned an 'executing' task — it would be re-executed after restart")
		}
	}
}

// TestResetInterruptedTasks confirms 'executing' tasks are moved to 'failed'
// with the correct note, is_synced=0, and attempt_count=MaxRetryAttempts.
func TestResetInterruptedTasks(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-interrupted", "assigned")
	if err := ts.MarkTaskExecuting("task-interrupted"); err != nil {
		t.Fatalf("MarkTaskExecuting: %v", err)
	}

	n, err := ts.ResetInterruptedTasks()
	if err != nil {
		t.Fatalf("ResetInterruptedTasks: %v", err)
	}
	if n != 1 {
		t.Errorf("ResetInterruptedTasks affected %d rows, want 1", n)
	}

	if got := queryStatus(t, ts, "task-interrupted"); got != "failed" {
		t.Errorf("status = %q, want %q", got, "failed")
	}
	if got := queryIsSynced(t, ts, "task-interrupted"); got != 0 {
		t.Errorf("is_synced = %d, want 0 (needs server sync)", got)
	}
	if got := queryAttemptCount(t, ts, "task-interrupted"); got != MaxRetryAttempts {
		t.Errorf("attempt_count = %d, want %d (max so it isn't auto-retried)", got, MaxRetryAttempts)
	}
}

// TestResetInterruptedTasks_NeverRetried confirms that after ResetInterruptedTasks,
// ResetOldFailedTasks will NOT recycle the task back to 'assigned'.
func TestResetInterruptedTasks_NeverRetried(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-reboot", "assigned")
	if err := ts.MarkTaskExecuting("task-reboot"); err != nil {
		t.Fatalf("MarkTaskExecuting: %v", err)
	}
	if _, err := ts.ResetInterruptedTasks(); err != nil {
		t.Fatalf("ResetInterruptedTasks: %v", err)
	}

	// Simulate several startup cycles — should never move back to 'assigned'.
	for i := 0; i < 5; i++ {
		if _, err := ts.ResetOldFailedTasks(0); err != nil {
			t.Fatalf("ResetOldFailedTasks cycle %d: %v", i, err)
		}
		if got := queryStatus(t, ts, "task-reboot"); got != "failed" {
			t.Errorf("cycle %d: status = %q, want %q — interrupted task was recycled to re-execute", i, got, "failed")
		}
	}
}

// TestGetRetryableTasks verifies that failed tasks with old completed_at and
// attempt_count < MaxRetryAttempts are returned.
func TestGetRetryableTasks(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-retryable", "assigned")
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01T00:00:00Z', attempt_count=0 WHERE id=?",
		"task-retryable"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tasks, err := ts.GetRetryableTasks(0)
	if err != nil {
		t.Fatalf("GetRetryableTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Errorf("got %d tasks, want 1", len(tasks))
	}
	if len(tasks) > 0 && tasks[0].ID != "task-retryable" {
		t.Errorf("task ID = %q, want task-retryable", tasks[0].ID)
	}
}

// TestGetRetryableTasks_AtMaxAttempts verifies that tasks at MaxRetryAttempts are excluded.
func TestGetRetryableTasks_AtMaxAttempts(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-maxed", "assigned")
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01T00:00:00Z', attempt_count=? WHERE id=?",
		MaxRetryAttempts, "task-maxed"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tasks, err := ts.GetRetryableTasks(0)
	if err != nil {
		t.Fatalf("GetRetryableTasks: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("got %d tasks, want 0 (task at max attempts should be excluded)", len(tasks))
	}
}

// TestResetOldFailedTasks verifies that old failed tasks are reset to 'assigned'
// while tasks at MaxRetryAttempts are left alone.
func TestResetOldFailedTasks(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-old", "assigned")
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01T00:00:00Z', attempt_count=0 WHERE id=?",
		"task-old"); err != nil {
		t.Fatalf("setup old task: %v", err)
	}
	seedTask(t, ts, "task-maxed", "assigned")
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01T00:00:00Z', attempt_count=? WHERE id=?",
		MaxRetryAttempts, "task-maxed"); err != nil {
		t.Fatalf("setup maxed task: %v", err)
	}

	n, err := ts.ResetOldFailedTasks(0)
	if err != nil {
		t.Fatalf("ResetOldFailedTasks: %v", err)
	}
	if n != 1 {
		t.Errorf("affected %d rows, want 1", n)
	}
	if got := queryStatus(t, ts, "task-old"); got != "assigned" {
		t.Errorf("task-old status = %q, want assigned", got)
	}
	if got := queryAttemptCount(t, ts, "task-old"); got != 1 {
		t.Errorf("task-old attempt_count = %d, want 1", got)
	}
	if got := queryStatus(t, ts, "task-maxed"); got != "failed" {
		t.Errorf("task-maxed status = %q, want failed (should not be reset)", got)
	}
}

// TestGetUnsyncedTasks verifies only unsynced completed tasks are returned.
func TestGetUnsyncedTasks(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-unsynced", "assigned")
	seedTask(t, ts, "task-synced", "assigned")
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01', is_synced=0 WHERE id=?",
		"task-unsynced"); err != nil {
		t.Fatalf("setup unsynced: %v", err)
	}
	if _, err := ts.db.Exec(
		"UPDATE tasks SET status='failed', completed_at='2020-01-01', is_synced=1 WHERE id=?",
		"task-synced"); err != nil {
		t.Fatalf("setup synced: %v", err)
	}

	tasks, err := ts.GetUnsyncedTasks()
	if err != nil {
		t.Fatalf("GetUnsyncedTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Errorf("got %d unsynced tasks, want 1", len(tasks))
	}
	if len(tasks) > 0 && tasks[0].ID != "task-unsynced" {
		t.Errorf("task ID = %q, want task-unsynced", tasks[0].ID)
	}
}

// TestMarkTaskSynced verifies MarkTaskSynced sets is_synced=1.
func TestMarkTaskSynced(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-1", "assigned")

	if err := ts.MarkTaskSynced("task-1"); err != nil {
		t.Fatalf("MarkTaskSynced: %v", err)
	}
	if got := queryIsSynced(t, ts, "task-1"); got != 1 {
		t.Errorf("is_synced = %d, want 1", got)
	}
}

// TestShowTasks verifies ShowTasks writes task rows to stdout.
func TestShowTasks(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-show-1", "assigned")
	seedTask(t, ts, "task-show-2", "assigned")

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	showErr := ts.ShowTasks()

	_ = w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	_ = r.Close()

	if showErr != nil {
		t.Fatalf("ShowTasks: %v", showErr)
	}
	output := buf.String()
	if !strings.Contains(output, "task-show-1") {
		t.Errorf("output missing task-show-1:\n%s", output)
	}
	if !strings.Contains(output, "task-show-2") {
		t.Errorf("output missing task-show-2:\n%s", output)
	}
}

// TestResetInterruptedTasks_IgnoresOtherStatuses confirms that 'assigned', 'success',
// and 'failed' tasks are untouched by ResetInterruptedTasks.
func TestResetInterruptedTasks_IgnoresOtherStatuses(t *testing.T) {
	ts := newTaskStoreForTest(t)
	seedTask(t, ts, "task-assigned", "assigned")
	seedTask(t, ts, "task-success", "assigned")
	seedTask(t, ts, "task-failed", "assigned")

	_ = ts.UpdateTaskStatus("task-success", "success", "", true)
	_ = ts.UpdateTaskStatus("task-failed", "failed", "err", false)

	n, err := ts.ResetInterruptedTasks()
	if err != nil {
		t.Fatalf("ResetInterruptedTasks: %v", err)
	}
	if n != 0 {
		t.Errorf("ResetInterruptedTasks affected %d rows, want 0 (no 'executing' tasks)", n)
	}

	if got := queryStatus(t, ts, "task-assigned"); got != "assigned" {
		t.Errorf("assigned task changed to %q", got)
	}
	if got := queryStatus(t, ts, "task-success"); got != "success" {
		t.Errorf("success task changed to %q", got)
	}
	if got := queryStatus(t, ts, "task-failed"); got != "failed" {
		t.Errorf("failed task changed to %q", got)
	}
}
