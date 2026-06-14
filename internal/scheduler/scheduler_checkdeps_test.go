package scheduler

import (
	"testing"
	"time"
)

// TestCheckDependencies_NoDeps verifies that a task with no dependencies always passes.
func TestCheckDependencies_NoDeps(t *testing.T) {
	s := NewScheduler()
	task := &Task{
		Name:         "target",
		Dependencies: []string{},
		Enabled:      true,
	}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if !s.checkDependencies(task) {
		t.Error("checkDependencies() = false for task with no dependencies; want true")
	}
}

// TestCheckDependencies_DepNotFound verifies that a missing dependency returns false.
func TestCheckDependencies_DepNotFound(t *testing.T) {
	s := NewScheduler()
	target := &Task{
		Name:         "target",
		Dependencies: []string{"nonexistent-dep"},
		Enabled:      true,
	}
	s.tasks["target"] = target // bypass AddTask to avoid calculateTaskOrder error

	if s.checkDependencies(target) {
		t.Error("checkDependencies() = true for missing dependency; want false")
	}
}

// TestCheckDependencies_DepNotYetRun verifies that a dependency that has never run returns false.
func TestCheckDependencies_DepNotYetRun(t *testing.T) {
	s := NewScheduler()
	dep := &Task{
		Name:    "dep",
		Enabled: true,
		// LastRun is zero-value — never run
	}
	target := &Task{
		Name:         "target",
		Dependencies: []string{"dep"},
		Enabled:      true,
	}
	s.tasks["dep"] = dep
	s.tasks["target"] = target

	if s.checkDependencies(target) {
		t.Error("checkDependencies() = true when dep has never run; want false")
	}
}

// TestCheckDependencies_DepHasRun verifies that a dependency that has run returns true.
func TestCheckDependencies_DepHasRun(t *testing.T) {
	s := NewScheduler()
	dep := &Task{
		Name:    "dep",
		Enabled: true,
		LastRun: time.Now().Add(-1 * time.Second), // ran 1 second ago
	}
	target := &Task{
		Name:         "target",
		Dependencies: []string{"dep"},
		Enabled:      true,
	}
	s.tasks["dep"] = dep
	s.tasks["target"] = target

	if !s.checkDependencies(target) {
		t.Error("checkDependencies() = false when dep has already run; want true")
	}
}
