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
	"sentinelgo/internal/lockfile"
)

func resetHealthState(t *testing.T) {
	t.Helper()
	reset := func() {
		healthMu.Lock()
		healthy, confirmed = false, false
		healthMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// stubSpawn records watchdog starts for tests that don't use the fixture.
func stubSpawn(t *testing.T) *[]string {
	t.Helper()
	var spawned []string
	prev := spawnWatchdogFn
	spawnWatchdogFn = func(_ *Marker, p string) error { spawned = append(spawned, p); return nil }
	t.Cleanup(func() { spawnWatchdogFn = prev })
	return &spawned
}

// ── CheckAndApply with the health watch ─────────────────────────────────────

// Without a running watchdog nothing could roll back a new binary that
// can't start, so the update doesn't go ahead.
func TestCheckAndApply_WatchdogSpawnFailureRefusesUpdate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	f.spawnErr = errors.New("no systemd-run")
	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "watchdog didn't start") {
		t.Fatalf("CheckAndApply() = %v, want a refusal", err)
	}
	if len(f.restarted) != 0 {
		t.Errorf("restarted = %v, want none", f.restarted)
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("binary replaced: %q", got)
	}
	assertNotExist(t, filepath.Join(f.cfgDir, markerFileName), "marker")
	assertNotExist(t, f.self+".backup", "backup")
	assertNotExist(t, watchdogPathFor(f.self), "watchdog copy")
}

func TestCheckAndApply_DowngradeIsNotWatched(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	config.Version = "v100.0.0"
	f.release.AllowDowngrade = true
	if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 1 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want the rollback installed", err, f.restarted)
	}
	// The older release may predate the health check: no marker, no
	// watchdog, no backup kept.
	assertNotExist(t, filepath.Join(f.cfgDir, markerFileName), "marker")
	assertNotExist(t, f.self+".backup", "backup")
	if len(f.spawned) != 0 {
		t.Errorf("watchdog spawned for a downgrade: %v", f.spawned)
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

// healthSetup writes a marker for an update v1.0.0 -> 2.0.0 (manifest
// spelling without the v) with a backup and a watchdog copy, and runs as
// v2.0.0.
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
		FromVersion: "v1.0.0", ToVersion: "2.0.0", ExePath: exe, BackupPath: exe + ".backup",
		WatchdogPath: watchdogPathFor(exe), HealthPath: filepath.Join(dir, healthFileName),
		RecordPath: filepath.Join(dir, rollbackFileName),
		Deadline:   time.Now().Add(HealthWindow), GiveUpAt: time.Now().Add(maxOfflineWait), MaxAttempts: MaxBootAttempts,
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

func readHealth(t *testing.T, m *Marker) HealthState {
	t.Helper()
	var h HealthState
	if err := readJSON(m.HealthPath, &h); err != nil {
		t.Fatalf("health file: %v", err)
	}
	return h
}

func TestStartHealthCheck_CountsBootAttempts(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	stubSpawn(t)
	for want := 1; want <= 2; want++ {
		StartHealthCheck(t.Context(), cfg)
		if h := readHealth(t, m); h.Attempts != want || h.BootedAt.IsZero() || h.AliveAt.IsZero() {
			t.Fatalf("after start %d: health %+v", want, h)
		}
	}
	// The marker itself is never rewritten by the agent.
	if got, _ := ReadMarker(markerPath); got == nil || !got.Created.Equal(m.Created) || got.ToVersion != m.ToVersion {
		t.Errorf("marker changed: %+v", got)
	}
	// The old binary (restored, or the update never took) doesn't count.
	config.Version = "v1.0.0"
	StartHealthCheck(t.Context(), cfg)
	if h := readHealth(t, m); h.Attempts != 2 {
		t.Errorf("attempts = %d after the old binary started, want 2", h.Attempts)
	}
}

// After a reboot no watchdog runs: the new binary starts one, unless one
// already holds the watchdog lock.
func TestStartHealthCheck_StartsWatchdogWhenNoneRuns(t *testing.T) {
	cfg, markerPath, _ := healthSetup(t)
	spawned := stubSpawn(t)
	StartHealthCheck(t.Context(), cfg)
	if len(*spawned) != 1 || (*spawned)[0] != markerPath {
		t.Fatalf("spawned %v, want one watchdog for %s", *spawned, markerPath)
	}

	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	StartHealthCheck(t.Context(), cfg)
	if len(*spawned) != 1 {
		t.Errorf("spawned %v while a watchdog holds the lock", *spawned)
	}
}

func TestConfirmHealthy_RemovesUpdateFiles(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	stubSpawn(t)
	StartHealthCheck(t.Context(), cfg)
	ConfirmHealthy(cfg)
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.HealthPath, "health file")
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

// A failed marker deletion is retried by the alive ticker, and alive marks
// continue meanwhile.
func TestConfirmHealthy_RetriesFailedCleanup(t *testing.T) {
	_, markerPath, m := healthSetup(t)
	// A directory where the marker is can't be removed with os.Remove while
	// it has an entry; swap the marker for one to make the deletion fail.
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(markerPath, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	healthMu.Lock()
	healthy = true
	ok := finishConfirm(m)
	healthMu.Unlock()
	if ok || confirmed {
		t.Fatal("confirmation reported done although the marker is still there")
	}
	if !healthTick(m) {
		t.Fatal("healthTick gave up while the marker remains")
	}
	// The marker is readable and removable again.
	if err := os.RemoveAll(markerPath); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	if healthTick(m) || !confirmed {
		t.Fatal("healthTick didn't finish the confirmation once the marker could go")
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.BackupPath, "backup")
}

// While the watchdog holds the transition lock (rolling back), the agent
// doesn't confirm; the alive ticker retries once the lock is free.
func TestConfirmHealthy_WaitsWhileWatchdogHoldsLock(t *testing.T) {
	cfg, markerPath, m := healthSetup(t)
	held, err := acquireTransition(markerPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	ConfirmHealthy(cfg) // waits confirmLockWait, then gives up for now
	if _, err := ReadMarker(markerPath); err != nil {
		t.Fatalf("marker removed while the watchdog held the lock: %v", err)
	}
	if _, err := os.Stat(m.BackupPath); err != nil {
		t.Fatalf("backup removed while the watchdog held the lock: %v", err)
	}
	_ = held.Release()
	if healthTick(m) || !confirmed {
		t.Fatal("the confirmation wasn't retried once the lock was free")
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.BackupPath, "backup")
}

// The watchdog rolled the update back while the agent was confirming: the
// agent leaves the restored state alone.
func TestFinishConfirm_AfterRollbackLeavesFilesAlone(t *testing.T) {
	_, markerPath, m := healthSetup(t)
	if err := os.Remove(markerPath); err != nil { // the watchdog's rollback
		t.Fatal(err)
	}
	healthMu.Lock()
	ok := finishConfirm(m)
	healthMu.Unlock()
	if !ok || !confirmed {
		t.Fatal("finishConfirm kept retrying after the update ended")
	}
	if _, err := os.Stat(m.BackupPath); err != nil {
		t.Errorf("backup removed after a rollback: %v", err)
	}
	// Another update's marker isn't this one's to remove either.
	resetHealthState(t)
	other := *m
	other.Created = m.Created.Add(time.Hour)
	if err := writeJSONAtomic(markerPath, &other); err != nil {
		t.Fatal(err)
	}
	healthMu.Lock()
	ok = finishConfirm(m)
	healthMu.Unlock()
	if !ok {
		t.Fatal("finishConfirm kept retrying on another update's marker")
	}
	if _, err := ReadMarker(markerPath); err != nil {
		t.Errorf("another update's marker removed: %v", err)
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
	var r RollbackRecord
	if err := readJSON(recPath, &r); err != nil || !r.Logged {
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
	starts     int
	// onLock runs when the watchdog takes the transition lock (the real
	// one, not waiting), e.g. to confirm the update just before it.
	onLock func()
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
		start:   func() error { w.starts++; return nil },
		lock: func(markerPath string) (func(), error) {
			if w.onLock != nil {
				w.onLock()
			}
			l, err := acquireTransition(markerPath, 0)
			if err != nil {
				return nil, err
			}
			return func() { _ = l.Release() }, nil
		},
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
		HealthPath: filepath.Join(dir, healthFileName), RecordPath: filepath.Join(dir, rollbackFileName),
		ProbeURL: "https://example.invalid",
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

// setHealth writes the new binary's health file (as the agent would).
func setHealth(t *testing.T, m *Marker, h HealthState) {
	t.Helper()
	h.Version = "2.0.0" // spelled differently from the marker on purpose
	if err := writeJSONAtomic(m.HealthPath, h); err != nil {
		t.Fatal(err)
	}
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
	assertNotExist(t, m.HealthPath, "health file")
	assertNotExist(t, m.BackupPath, "backup")
	var r RollbackRecord
	err := readJSON(m.RecordPath, &r)
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
	markerPath, m, w := watchdogSetup(t, nil)
	setHealth(t, m, HealthState{Attempts: MaxBootAttempts + 1, BootedAt: w.now, AliveAt: w.now})
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "started 4 times")
	if w.sleeps != 0 {
		t.Errorf("waited %d polls before acting on a crash loop", w.sleeps)
	}
}

// The new binary keeps marking itself alive.
func keepAlive(t *testing.T, m *Marker, w *fakeWatchdog, booted time.Time) func(int) {
	markerPath := filepath.Join(filepath.Dir(m.HealthPath), markerFileName)
	return func(int) {
		if _, err := os.Stat(markerPath); err == nil { // until a rollback
			setHealth(t, m, HealthState{Attempts: 1, BootedAt: booted, AliveAt: w.now})
		}
	}
}

func TestWatchdog_RunningButUnhealthyWithNetworkRollsBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.onSleep = keepAlive(t, m, w, w.now)
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "running but not signed in")
}

// After a reboot the new binary starts again late: it gets a fresh window
// from that start, not the original deadline.
func TestWatchdog_FreshWindowAfterLateStart(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	booted := w.now.Add(HealthWindow - time.Minute)
	setHealth(t, m, HealthState{Attempts: 1, BootedAt: booted, AliveAt: booted})
	w.onSleep = keepAlive(t, m, w, booted)
	code := runWatchdog(markerPath, w.deps())
	assertRolledBack(t, markerPath, m, w, code, "running but not signed in")
	if elapsed := w.now.Sub(booted); elapsed < HealthWindow {
		t.Errorf("rolled back %s after the late start, want at least %s", elapsed, HealthWindow)
	}
}

func TestWatchdog_OfflineExtendsDeadline(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.networkUp = false
	start := w.now
	alive := keepAlive(t, m, w, start)
	w.onSleep = func(n int) {
		alive(n)
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
	// The watchdog never writes the marker (only the old binary does, once).
	if _, err := os.Stat(markerPath); err == nil {
		t.Error("marker still there")
	}
}

func TestWatchdog_OfflinePastGiveUpRollsBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, func(m *Marker) { m.GiveUpAt = m.Deadline })
	w.networkUp = false
	w.onSleep = keepAlive(t, m, w, w.now)
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
	// The service may be down (the Windows script starts it only after a
	// successful swap): it is started, not left stopped.
	if w.starts != 1 {
		t.Errorf("starts = %d, want 1", w.starts)
	}
	assertNotExist(t, markerPath, "marker")
	assertNotExist(t, m.RecordPath, "rollback record")
}

// The agent confirmed the update healthy just before the watchdog took the
// transition lock: no rollback.
func TestWatchdog_ConfirmedBeforeLockDoesNotRollBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.onLock = func() { _ = os.Remove(markerPath) }
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 0 || w.restarts != 0 {
		t.Fatalf("exit %d, installs %d, restarts %d; want a quiet exit", code, w.installs, w.restarts)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("binary changed: %q", got)
	}
	assertNotExist(t, m.RecordPath, "rollback record")
}

// While the agent holds the transition lock (confirming), the watchdog
// doesn't roll back; it acts once the lock is free and the update is still
// unconfirmed.
func TestWatchdog_WaitsForTransitionLock(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	held, err := acquireTransition(markerPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	w.onSleep = func(int) {
		if !released && w.installs == 0 && w.now.After(m.Deadline) {
			_ = held.Release()
			released = true
		}
	}
	t.Cleanup(func() { _ = held.Release() })
	// Past the deadline the first lock attempt fails; the poll after it
	// releases the lock.
	w.now = m.Deadline.Add(time.Minute)
	code := runWatchdog(markerPath, w.deps())
	if !released || w.sleeps == 0 {
		t.Fatalf("rolled back without waiting for the lock (sleeps %d)", w.sleeps)
	}
	assertRolledBack(t, markerPath, m, w, code, "not running")
}

// If the rollback record can't be written, the bad version stays blocked:
// the marker is renamed rather than deleted.
func TestWatchdog_RecordWriteFailureKeepsGuard(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, func(m *Marker) {
		m.RecordPath = filepath.Join(filepath.Dir(m.ExePath), "missing-dir", rollbackFileName)
	})
	if code := runWatchdog(markerPath, w.deps()); code != 0 || w.installs != 1 || w.restarts != 1 {
		t.Fatalf("exit %d, installs %d, restarts %d; want a rollback", code, w.installs, w.restarts)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "good old agent" {
		t.Errorf("binary = %q, want the backup", got)
	}
	assertNotExist(t, markerPath, "marker")
	cfg := &config.Config{Path: filepath.Join(filepath.Dir(markerPath), "config.json")}
	if got := rolledBackVersion(cfg); got != "v2.0.0" {
		t.Fatalf("rolledBackVersion = %q, want v2.0.0 from the renamed marker", got)
	}
	if !heldBack(cfg, "2.0.0") {
		t.Error("the rolled-back version isn't held back")
	}
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

// Only one watchdog runs per marker.
func TestRunWatchdog_SecondInstanceExits(t *testing.T) {
	markerPath, m, _ := watchdogSetup(t, nil)
	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	if code := RunWatchdog(markerPath); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("second watchdog acted: %q", got)
	}
}

// writeJSONAtomic uses a temp file of its own per write, so writers never
// share one.
func TestWriteJSONAtomic_NoSharedTempFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	for i := range 3 {
		if err := writeJSONAtomic(p, map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("files left: %v", entries)
	}
}
