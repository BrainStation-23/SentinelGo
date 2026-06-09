package store

import (
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/taskstore"
)

// ── formatTime ────────────────────────────────────────────────────────────────

func TestFormatTime_Nil(t *testing.T) {
	if got := formatTime(nil); got != "" {
		t.Errorf("formatTime(nil) = %q, want %q", got, "")
	}
}

func TestFormatTime_Valid(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	got := formatTime(&ts)
	want := "2024-01-15T10:30:00Z"
	if got != want {
		t.Errorf("formatTime() = %q, want %q", got, want)
	}
}

func TestFormatTime_ConvertsToUTC(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("America/New_York timezone not available")
	}
	// 5:30 AM EST is 10:30 AM UTC
	ts := time.Date(2024, 1, 15, 5, 30, 0, 0, loc)
	got := formatTime(&ts)
	want := "2024-01-15T10:30:00Z"
	if got != want {
		t.Errorf("formatTime() UTC conversion = %q, want %q", got, want)
	}
}

// ── parseTime ────────────────────────────────────────────────────────────────

func TestParseTime_Nil(t *testing.T) {
	if got := parseTime(nil); got != nil {
		t.Errorf("parseTime(nil) = %v, want nil", got)
	}
}

func TestParseTime_Empty(t *testing.T) {
	if got := parseTime([]byte{}); got != nil {
		t.Errorf("parseTime(empty) = %v, want nil", got)
	}
}

func TestParseTime_Valid(t *testing.T) {
	got := parseTime([]byte("2024-01-15T10:30:00Z"))
	if got == nil {
		t.Fatal("parseTime() returned nil for valid input")
	}
	want := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseTime() = %v, want %v", got, want)
	}
}

func TestParseTime_Invalid(t *testing.T) {
	if got := parseTime([]byte("not-a-date")); got != nil {
		t.Errorf("parseTime(invalid) = %v, want nil", got)
	}
}

// ── truncateString ───────────────────────────────────────────────────────────

func TestTruncateString_Short(t *testing.T) {
	got := truncateString("hello", 10)
	if got != "hello" {
		t.Errorf("truncateString(short) = %q, want %q", got, "hello")
	}
}

func TestTruncateString_Exact(t *testing.T) {
	got := truncateString("hello", 5)
	if got != "hello" {
		t.Errorf("truncateString(exact) = %q, want %q", got, "hello")
	}
}

func TestTruncateString_Long(t *testing.T) {
	got := truncateString("hello world", 8)
	want := "hello..."
	if got != want {
		t.Errorf("truncateString(long) = %q, want %q", got, want)
	}
}

func TestTruncateString_Empty(t *testing.T) {
	got := truncateString("", 5)
	if got != "" {
		t.Errorf("truncateString(empty) = %q, want %q", got, "")
	}
}

// ── min ──────────────────────────────────────────────────────────────────────

func TestStoreMin_AltB(t *testing.T) {
	if got := min(3, 7); got != 3 {
		t.Errorf("min(3,7) = %d, want 3", got)
	}
}

func TestStoreMin_AgtB(t *testing.T) {
	if got := min(7, 3); got != 3 {
		t.Errorf("min(7,3) = %d, want 3", got)
	}
}

func TestStoreMin_Equal(t *testing.T) {
	if got := min(5, 5); got != 5 {
		t.Errorf("min(5,5) = %d, want 5", got)
	}
}

func TestStoreMin_Negative(t *testing.T) {
	if got := min(-3, -7); got != -7 {
		t.Errorf("min(-3,-7) = %d, want -7", got)
	}
}

// ── ClearCompletedTasks ───────────────────────────────────────────────────────

func TestClearCompletedTasks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks_clear_test.db")
	ts, err := NewTaskStore(path)
	if err != nil {
		t.Fatalf("NewTaskStore: %v", err)
	}
	defer func() { _ = ts.Close() }()

	tasks := []taskstore.Task{
		{ID: "task-success", Name: "Success Task", Status: "assigned"},
		{ID: "task-failed", Name: "Failed Task", Status: "assigned"},
		{ID: "task-pending", Name: "Pending Task", Status: "assigned"},
	}
	if err := ts.StoreTasks(tasks); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}

	if err := ts.UpdateTaskStatus("task-success", "success", "", false); err != nil {
		t.Fatalf("UpdateTaskStatus success: %v", err)
	}
	if err := ts.UpdateTaskStatus("task-failed", "failed", "error msg", false); err != nil {
		t.Fatalf("UpdateTaskStatus failed: %v", err)
	}

	// Purge tasks completed before now+1s (covers both task-success and task-failed).
	if err := ts.ClearCompletedTasks(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("ClearCompletedTasks: %v", err)
	}

	// The pending task should still be present; completed tasks should be gone.
	var completedCount int
	if err := ts.db.QueryRow(
		"SELECT COUNT(*) FROM tasks WHERE status IN ('success', 'failed')",
	).Scan(&completedCount); err != nil {
		t.Fatalf("count completed tasks: %v", err)
	}
	if completedCount != 0 {
		t.Errorf("completed task count after ClearCompletedTasks = %d, want 0", completedCount)
	}

	var pendingCount int
	if err := ts.db.QueryRow(
		"SELECT COUNT(*) FROM tasks WHERE id = 'task-pending'",
	).Scan(&pendingCount); err != nil {
		t.Fatalf("count pending tasks: %v", err)
	}
	if pendingCount != 1 {
		t.Errorf("pending task count after ClearCompletedTasks = %d, want 1", pendingCount)
	}
}

func TestClearCompletedTasks_FutureOlderThan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks_future_test.db")
	ts, err := NewTaskStore(path)
	if err != nil {
		t.Fatalf("NewTaskStore: %v", err)
	}
	defer func() { _ = ts.Close() }()

	tasks := []taskstore.Task{
		{ID: "task-1", Name: "Task 1", Status: "assigned"},
	}
	if err := ts.StoreTasks(tasks); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}
	if err := ts.UpdateTaskStatus("task-1", "success", "", false); err != nil {
		t.Fatalf("UpdateTaskStatus: %v", err)
	}

	// olderThan in the past — task-1 was just completed so it won't be deleted.
	past := time.Now().Add(-time.Hour)
	if err := ts.ClearCompletedTasks(past); err != nil {
		t.Fatalf("ClearCompletedTasks: %v", err)
	}

	var count int
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM tasks WHERE id = 'task-1'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("task-1 should NOT have been deleted (olderThan is in the past), got count=%d", count)
	}
}
