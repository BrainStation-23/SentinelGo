package epm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Crash-loop guard tuning. See CheckProbation and RecordBundleBoot.
const (
	probationBootThreshold = 3
	probationWindow        = 10 * time.Minute
	probationClearAfter    = 30 * time.Minute
)

// probationState is the on-disk shape of the crash-loop guard, written next
// to the EPM database (same idiom as emergencylog.Init — a small JSON file
// in the config directory, not a database row, so it can be read before any
// store is opened and survives even if the store itself is what's broken).
type probationState struct {
	BundleID    string    `json:"bundle_id"`
	ActivatedAt time.Time `json:"activated_at"`
	BootCount   int       `json:"boot_count"`
}

func loadProbationState(path string) (*probationState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s probationState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse probation state: %w", err)
	}
	return &s, nil
}

// saveProbationState writes via temp-file-plus-rename, the same atomic-write
// idiom internal/config.Config.SaveAtomic uses, so a crash mid-write never
// leaves a half-written, unparseable state file behind.
func saveProbationState(path string, s *probationState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create probation state dir: %w", err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal probation state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write probation state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename probation state into place: %w", err)
	}
	return nil
}

// RecordBundleBoot increments the crash-loop guard's boot counter for the
// currently-active bundle. Call exactly once per agent startup, before
// BundleManager.Apply is given any new work — this is what actually detects
// a crash loop; BundleManager.Apply itself only resets the counter to 1 when
// a genuinely new bundle activates (see recordProbation), since a deliberate
// policy change is not a crash.
//
// bundleID is the caller's own record of which bundle is currently active
// (from BundlePersistence.ActiveBundle, or wherever the caller tracks it) —
// RecordBundleBoot does not query persistence itself, keeping this package's
// only file I/O centralized in this one small state file rather than mixed
// with SQLite access.
func RecordBundleBoot(path, bundleID string) {
	if path == "" || bundleID == "" {
		return
	}
	state, err := loadProbationState(path)
	if err != nil || state.BundleID != bundleID {
		state = &probationState{BundleID: bundleID, ActivatedAt: time.Now().UTC(), BootCount: 0}
	}
	state.BootCount++
	if err := saveProbationState(path, state); err != nil {
		// Best effort: a write failure here means the crash-loop guard
		// degrades to "not enforced this boot," never a startup failure.
		return
	}
}

// CheckProbation inspects the crash-loop guard's state file and reports
// whether the agent should revert to the previous active bundle: true when
// the recorded bundle has booted probationBootThreshold or more times within
// probationWindow of its first recorded activation. Call after
// RecordBundleBoot, early at startup, before any new bundle is applied.
//
// A bundle that has run stably for probationClearAfter since activation is
// no longer "on probation" — CheckProbation returns false and clears the
// state file as a side effect, so an old, long-stable bundle does not trip
// this guard on an unrelated restart (an OS reboot, a manual service
// restart) long after it proved itself.
func CheckProbation(path string) (shouldRollback bool, bundleID string) {
	if path == "" {
		return false, ""
	}
	state, err := loadProbationState(path)
	if err != nil || state.BundleID == "" {
		return false, ""
	}
	if time.Since(state.ActivatedAt) > probationClearAfter {
		_ = os.Remove(path)
		return false, ""
	}
	if state.BootCount >= probationBootThreshold && time.Since(state.ActivatedAt) <= probationWindow {
		return true, state.BundleID
	}
	return false, ""
}

// ClearProbation removes the crash-loop guard's state file — call after a
// successful rollback (so the bundle being reverted TO starts its own fresh
// window), or whenever an operator explicitly re-activates the bundle
// currently on probation, deliberately accepting the risk.
func ClearProbation(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
}
