package scheduler

import (
	"errors"
	"testing"
)

// TestObserveTaskResult verifies the consecutive-failure counter and the
// single-alert / single-recovery gating used to feed the emergency log.
// emergencylog is uninitialized here, so Record is a harmless no-op (echo only).
func TestObserveTaskResult(t *testing.T) {
	task := &Task{Name: "software-sync"}
	boom := errors.New("backend unreachable")

	// Below threshold: counts up, no alert yet.
	for i := 1; i < taskFailureThreshold; i++ {
		observeTaskResult(task, boom)
		if got := task.consecutiveFailures.Load(); got != int32(i) {
			t.Fatalf("after %d failures: counter=%d, want %d", i, got, i)
		}
		if task.alerted.Load() {
			t.Fatalf("alerted set before reaching threshold (%d failures)", i)
		}
	}

	// Crossing the threshold: alerts exactly once.
	observeTaskResult(task, boom)
	if got := task.consecutiveFailures.Load(); got != taskFailureThreshold {
		t.Fatalf("at threshold: counter=%d, want %d", got, taskFailureThreshold)
	}
	if !task.alerted.Load() {
		t.Fatal("expected alerted to be set once threshold reached")
	}

	// Further failures keep climbing but stay alerted (no re-alert).
	observeTaskResult(task, boom)
	if got := task.consecutiveFailures.Load(); got != taskFailureThreshold+1 {
		t.Fatalf("after extra failure: counter=%d, want %d", got, taskFailureThreshold+1)
	}
	if !task.alerted.Load() {
		t.Fatal("alerted should remain set during a sustained outage")
	}

	// First success: resets counter and clears the alert (recovery line emitted).
	observeTaskResult(task, nil)
	if got := task.consecutiveFailures.Load(); got != 0 {
		t.Fatalf("after recovery: counter=%d, want 0", got)
	}
	if task.alerted.Load() {
		t.Fatal("alerted should be cleared after recovery")
	}

	// A new failure starts a fresh streak.
	observeTaskResult(task, boom)
	if got := task.consecutiveFailures.Load(); got != 1 {
		t.Fatalf("new streak: counter=%d, want 1", got)
	}
	if task.alerted.Load() {
		t.Fatal("alerted should stay clear after a single fresh failure")
	}
}
