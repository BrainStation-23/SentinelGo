package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// A marker that can't be read for a moment when the agent confirms doesn't
// lose the confirmation: the alive ticker finishes it, before the watchdog's
// deadline would roll the healthy update back.
func TestConfirmHealthy_TransientMarkerErrorRetriesFromTicker(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	stubSpawn(t)
	StartHealthCheck(t.Context(), cfg)
	good := mustReadFile(t, markerPath)
	if err := os.WriteFile(markerPath, []byte("{half-written"), 0o600); err != nil {
		t.Fatal(err)
	}
	ConfirmHealthy(cfg)
	if err := os.WriteFile(markerPath, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if more := healthTick(m); more {
		t.Fatal("the alive ticker didn't finish the confirmation")
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.BackupPath, "backup")
}

// expiredMarker writes a marker past GiveUpAt for v2.0.0 while v1.0.0 runs
// (the watchdog restored it but couldn't record or move the marker).
func expiredMarker(t *testing.T) (*config.Config, string) {
	t.Helper()
	resetHealthState(t)
	dir := t.TempDir()
	prev := config.Version
	config.Version = "v1.0.0"
	t.Cleanup(func() { config.Version = prev })
	m := Marker{FromVersion: "v1.0.0", ToVersion: "v2.0.0", HealthPath: filepath.Join(dir, healthFileName),
		GiveUpAt: time.Now().Add(-time.Minute)}
	markerPath := filepath.Join(dir, markerFileName)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	return &config.Config{Path: filepath.Join(dir, "config.json")}, markerPath
}

// Retiring an expired marker waits for the transition lock: while a
// watchdog holds it (rolling that update back), nothing is touched and no
// new update starts.
func TestPendingUpdate_ExpiredMarkerWaitsForTransitionLock(t *testing.T) {
	cfg, markerPath := expiredMarker(t)
	held, err := acquireTransition(markerPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	if _, pending := pendingUpdate(cfg, time.Now()); !pending {
		t.Error("an update may start while the watchdog holds the transition lock")
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("marker touched while the watchdog held the lock: %v", err)
	}
	_ = held.Release()
	if _, pending := pendingUpdate(cfg, time.Now()); pending {
		t.Error("still pending once the lock is free and the marker moved aside")
	}
}

// If the expired marker can't be moved aside, it is the only record of the
// bad version: no update (of any version) may overwrite it.
func TestHeldBack_ExpiredMarkerRenameFailsBlocksEveryUpdate(t *testing.T) {
	cfg, markerPath := expiredMarker(t)
	// A non-empty directory at the rolled-back name makes the rename fail.
	blocker := filepath.Join(filepath.Dir(markerPath), rolledBackMarkerName)
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !heldBack(cfg, "v3.0.0") {
		t.Error("a different update may run and overwrite the only guard for v2.0.0")
	}
	if !heldBack(cfg, "v2.0.0") {
		t.Error("v2.0.0 isn't blocked")
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("the guarding marker is gone: %v", err)
	}
}

// The watchdog decides again after taking the lock: a binary that started
// after the deadline but before the lock gets its fresh health window.
func TestWatchdog_RejudgesUnderLock(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.now = m.Deadline.Add(time.Minute) // not running past the deadline: a rollback reason
	started := false
	w.onLock = func() {
		if !started {
			started = true
			setHealth(t, m, HealthState{Attempts: 1, BootedAt: w.now, AliveAt: w.now})
		}
	}
	w.onSleep = func(int) { _ = os.Remove(markerPath) } // confirmed healthy next
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 0 {
		t.Fatalf("exit %d, installs %d; rolled back a binary that just started", code, w.installs)
	}
}
