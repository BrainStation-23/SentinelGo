package updater

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

func resetHealthState(t *testing.T) {
	t.Helper()
	healthMu.Lock()
	confirmed = false
	healthMu.Unlock()
	t.Cleanup(func() {
		healthMu.Lock()
		confirmed = false
		healthMu.Unlock()
	})
}

// ── CheckAndApply with the health watch ─────────────────────────────────────

func TestCheckAndApply_WatchdogSpawnFailureStillUpdates(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	f.spawnErr = errors.New("no systemd-run")
	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Fatalf("CheckAndApply() error: %v", err)
	}
	if len(f.restarted) != 1 {
		t.Errorf("restarted = %v, want one restart", f.restarted)
	}
	// The marker stays, so the new binary still cleans up once healthy.
	if _, err := ReadMarker(filepath.Join(f.cfgDir, markerFileName)); err != nil {
		t.Errorf("marker: %v", err)
	}
}

func TestCheckAndApply_SkipsRolledBackVersion(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	rec := RollbackRecord{BadVersion: "99.9.9", RestoredVersion: "v1.0.0", Reason: "test", Logged: true}
	if err := writeJSONAtomic(filepath.Join(f.cfgDir, rollbackFileName), rec); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Fatalf("CheckAndApply() error: %v", err)
	}
	if len(f.restarted) != 0 {
		t.Fatal("a rolled-back version was installed again")
	}
	assertNotExist(t, f.self+".backup", "backup")

	// The server offers another version: the record doesn't block it.
	rec.BadVersion = "v99.9.8"
	if err := writeJSONAtomic(filepath.Join(f.cfgDir, rollbackFileName), rec); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 1 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want an update to the other version", err, f.restarted)
	}
}

func TestCheckAndApply_WaitsForPendingUpdate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	markerPath := filepath.Join(f.cfgDir, markerFileName)
	m := Marker{FromVersion: "v0.9.0", ToVersion: "v1.0.0", GiveUpAt: time.Now().Add(time.Hour)}
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 0 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want no update while one is pending", err, f.restarted)
	}

	// A marker past GiveUpAt is stale: removed, and the update goes ahead.
	m.GiveUpAt = time.Now().Add(-time.Minute)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 1 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want the update after a stale marker", err, f.restarted)
	}
	if got, _ := ReadMarker(markerPath); got == nil || got.ToVersion != "v99.9.9" {
		t.Errorf("marker = %+v, want the new update's", got)
	}
}

func TestCheckAndApply_MarkerWriteFailureRefusesUpdate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	cfg.Path = filepath.Join(f.cfgDir, "missing-dir", "config.json")
	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "without a health check") {
		t.Fatalf("CheckAndApply() error = %v, want a refusal", err)
	}
	if len(f.restarted) != 0 || len(f.spawned) != 0 {
		t.Errorf("restarted %v, spawned %v; want neither", f.restarted, f.spawned)
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("self must be untouched, got %q", got)
	}
	assertNotExist(t, f.self+".backup", "backup")
	assertNotExist(t, watchdogPathFor(f.self), "watchdog copy")
}

// ── The new binary's side ───────────────────────────────────────────────────

// healthSetup writes a marker for an update v1.0.0 -> v2.0.0 with a backup and
// a watchdog copy, and runs as v2.0.0.
func healthSetup(t *testing.T) (*config.Config, string, *Marker) {
	t.Helper()
	resetHealthState(t)
	dir := t.TempDir()
	exe := fakeExecutable(t, []byte("new agent"))
	prev := config.Version
	config.Version = "v2.0.0"
	t.Cleanup(func() { config.Version = prev })
	cfg := &config.Config{Path: filepath.Join(dir, "config.json")}
	m := &Marker{
		FromVersion: "v1.0.0", ToVersion: "v2.0.0", ExePath: exe, BackupPath: exe + ".backup",
		WatchdogPath: watchdogPathFor(exe), RecordPath: filepath.Join(dir, rollbackFileName),
		Deadline: time.Now().Add(HealthWindow), GiveUpAt: time.Now().Add(maxOfflineWait), MaxAttempts: MaxBootAttempts,
	}
	for _, p := range []string{m.BackupPath, m.WatchdogPath} {
		if err := os.WriteFile(p, []byte("old agent"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	markerPath := filepath.Join(dir, markerFileName)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	return cfg, markerPath, m
}

func TestStartHealthCheck_CountsBootAttempts(t *testing.T) {
	cfg, markerPath, _ := healthSetup(t)
	for want := 1; want <= 2; want++ {
		StartHealthCheck(t.Context(), cfg)
		m, err := ReadMarker(markerPath)
		if err != nil || m.Attempts != want || m.AliveAt.IsZero() {
			t.Fatalf("after start %d: marker %+v, %v", want, m, err)
		}
	}
	// The old binary (restored, or the update never took) doesn't count.
	config.Version = "v1.0.0"
	StartHealthCheck(t.Context(), cfg)
	if m, _ := ReadMarker(markerPath); m.Attempts != 2 {
		t.Errorf("attempts = %d after the old binary started, want 2", m.Attempts)
	}
}

func TestConfirmHealthy_RemovesMarkerAndBackup(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	ConfirmHealthy(cfg)
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.BackupPath, "backup")
	assertNotExist(t, m.WatchdogPath, "watchdog copy")
}

func TestConfirmHealthy_IgnoresOtherVersionsMarker(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	config.Version = "v1.0.0" // the old binary is running: nothing to confirm
	ConfirmHealthy(cfg)
	if _, err := ReadMarker(markerPath); err != nil {
		t.Errorf("marker removed: %v", err)
	}
	if _, err := os.Stat(m.BackupPath); err != nil {
		t.Errorf("backup removed: %v", err)
	}
}

func TestStartHealthCheck_LogsRollbackOnce(t *testing.T) {
	resetHealthState(t)
	dir := t.TempDir()
	cfg := &config.Config{Path: filepath.Join(dir, "config.json")}
	recPath := filepath.Join(dir, rollbackFileName)
	if err := writeJSONAtomic(recPath, RollbackRecord{BadVersion: "v2.0.0", RestoredVersion: "v1.0.0", Reason: "crashed"}); err != nil {
		t.Fatal(err)
	}
	StartHealthCheck(t.Context(), cfg)
	r, err := readRollbackRecord(recPath)
	if err != nil || !r.Logged {
		t.Errorf("record = %+v, %v; want logged", r, err)
	}
	if got := rolledBackVersion(cfg); got != "v2.0.0" {
		t.Errorf("rolledBackVersion = %q", got)
	}
}

// ── Watchdog ────────────────────────────────────────────────────────────────

type fakeWatchdog struct {
	now        time.Time
	sleeps     int
	onSleep    func(n int)
	networkUp  bool
	installs   int
	installErr error
	restarts   int
}

func (w *fakeWatchdog) deps() watchdogDeps {
	return watchdogDeps{
		now: func() time.Time { return w.now },
		sleep: func(d time.Duration) {
			w.now = w.now.Add(d)
			w.sleeps++
			if w.onSleep != nil {
				w.onSleep(w.sleeps)
			}
		},
		networkUp: func(string) bool { return w.networkUp },
		install: func(m *Marker) error {
			w.installs++
			if w.installErr != nil {
				return w.installErr
			}
			return replaceWithBackup(m)
		},
		restart: func() error { w.restarts++; return nil },
	}
}

// watchdogSetup: the binary is the new release, the backup the old one.
func watchdogSetup(t *testing.T, edit func(m *Marker)) (string, *Marker, *fakeWatchdog) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "sentinelgo")
	if err := os.WriteFile(exe, []byte("broken new agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".backup", []byte("good old agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	m := &Marker{
		FromVersion: "v1.0.0", ToVersion: "v2.0.0", ExePath: exe, BackupPath: exe + ".backup",
		RecordPath: filepath.Join(dir, rollbackFileName), ProbeURL: "https://example.invalid",
		Deadline: now.Add(HealthWindow), GiveUpAt: now.Add(maxOfflineWait), MaxAttempts: MaxBootAttempts,
	}
	if edit != nil {
		edit(m)
	}
	markerPath := filepath.Join(dir, markerFileName)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	return markerPath, m, &fakeWatchdog{now: now, networkUp: true}
}

func assertRolledBack(t *testing.T, markerPath string, m *Marker, w *fakeWatchdog, code int, reason string) {
	t.Helper()
	if code != 0 || w.installs != 1 || w.restarts != 1 {
		t.Fatalf("exit %d, installs %d, restarts %d; want a rollback", code, w.installs, w.restarts)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "good old agent" {
		t.Errorf("binary = %q, want the backup", got)
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.BackupPath, "backup")
	r, err := readRollbackRecord(m.RecordPath)
	if err != nil || r.BadVersion != "v2.0.0" || r.RestoredVersion != "v1.0.0" || !strings.Contains(r.Reason, reason) || r.Logged {
		t.Errorf("record = %+v, %v; want bad v2.0.0 because %q", r, err, reason)
	}
}

func TestWatchdog_ExitsWhenHealthy(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.onSleep = func(n int) {
		if n == 3 {
			_ = os.Remove(markerPath) // ConfirmHealthy
		}
	}
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 0 || w.restarts != 0 {
		t.Fatalf("exit %d, installs %d, restarts %d; want a quiet exit", code, w.installs, w.restarts)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("binary changed: %q", got)
	}
}

func TestWatchdog_RollsBackAfterDeadline(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "not running")
}

func TestWatchdog_RollsBackCrashLoop(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, func(m *Marker) { m.Attempts = MaxBootAttempts + 1 })
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "started 4 times")
	if w.sleeps != 0 {
		t.Errorf("waited %d polls before acting on a crash loop", w.sleeps)
	}
}

func TestWatchdog_RunningButUnhealthyWithNetworkRollsBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.onSleep = func(int) { // the new binary keeps marking itself alive
		cur, _ := ReadMarker(markerPath)
		cur.AliveAt = w.now
		_ = writeJSONAtomic(markerPath, cur)
	}
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "running but not signed in")
}

func TestWatchdog_OfflineExtendsDeadline(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.networkUp = false
	start := w.now
	w.onSleep = func(int) {
		cur, err := ReadMarker(markerPath)
		if err != nil {
			return
		}
		cur.AliveAt = w.now
		_ = writeJSONAtomic(markerPath, cur)
		if w.now.Sub(start) > 3*HealthWindow {
			_ = os.Remove(markerPath) // back online and healthy
		}
	}
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 0 {
		t.Fatalf("exit %d, installs %d; want no rollback while offline", code, w.installs)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("binary changed: %q", got)
	}
}

func TestWatchdog_OfflinePastGiveUpRollsBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, func(m *Marker) { m.GiveUpAt = m.Deadline })
	w.networkUp = false
	w.onSleep = func(int) {
		cur, _ := ReadMarker(markerPath)
		cur.AliveAt = w.now
		_ = writeJSONAtomic(markerPath, cur)
	}
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "running but not signed in")
}

func TestWatchdog_UpdateNeverInstalled(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	if err := os.WriteFile(m.ExePath, []byte("good old agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 0 || w.restarts != 0 {
		t.Fatalf("exit %d, installs %d, restarts %d; want a cleanup only", code, w.installs, w.restarts)
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.RecordPath, "rollback record")
}

func TestWatchdog_InstallFailureKeepsBackup(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.installErr = errors.New("locked")
	if code := runWatchdog(markerPath, w.deps()); code != 1 || w.installs != 3 {
		t.Fatalf("exit %d, installs %d; want 3 failed attempts", code, w.installs)
	}
	if _, err := os.Stat(m.BackupPath); err != nil {
		t.Errorf("backup removed after a failed rollback: %v", err)
	}
	assertNotExist(t, m.RecordPath, "rollback record")
}

func TestWatchdog_RejectsTamperedMarker(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, func(m *Marker) { m.BackupPath = filepath.Join(filepath.Dir(m.ExePath), "evil") })
	if code := runWatchdog(markerPath, w.deps()); code != 1 || w.installs != 0 {
		t.Fatalf("exit %d, installs %d; want a refusal", code, w.installs)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("binary changed: %q", got)
	}
}
