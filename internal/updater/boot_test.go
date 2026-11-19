package updater

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
)

// The package's tests never touch the real boot job (schtasks, systemctl,
// /Library/LaunchDaemons): every test binary records registrations instead.
// The per-OS implementations are tested on their own with temp dirs and a
// fake command runner (boot_unix_test.go, boot_windows_test.go).
var bootCalls struct {
	sync.Mutex
	registered   []string // marker paths
	unregistered int
}

func init() {
	registerBootWatchdogFn = func(_ *Marker, markerPath string) error {
		bootCalls.Lock()
		defer bootCalls.Unlock()
		bootCalls.registered = append(bootCalls.registered, markerPath)
		return nil
	}
	unregisterBootWatchdogFn = func() error {
		bootCalls.Lock()
		defer bootCalls.Unlock()
		bootCalls.unregistered++
		return nil
	}
}

// resetBootCalls clears the recorded calls; it returns a reader of them.
func resetBootCalls(t *testing.T) func() (registered []string, unregistered int) {
	t.Helper()
	bootCalls.Lock()
	bootCalls.registered, bootCalls.unregistered = nil, 0
	bootCalls.Unlock()
	return func() ([]string, int) {
		bootCalls.Lock()
		defer bootCalls.Unlock()
		return append([]string(nil), bootCalls.registered...), bootCalls.unregistered
	}
}

// ── Boot job definitions ────────────────────────────────────────────────────

func bootMarker() *Marker {
	return &Marker{WatchdogPath: "/opt/sentinelgo/sentinelgo-update-watchdog", ExePath: "/opt/sentinelgo/sentinelgo"}
}

func TestSystemdUnit(t *testing.T) {
	u, err := systemdUnit(bootMarker(), "/opt/sentinelgo/.sentinelgo/update_marker.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/opt/sentinelgo/sentinelgo-update-watchdog" update-watchdog --marker "/opt/sentinelgo/.sentinelgo/update_marker.json" --boot`,
		"ConditionPathExists=/opt/sentinelgo/.sentinelgo/update_marker.json",
		"WantedBy=multi-user.target",
		"Type=simple",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// The boot job runs the watchdog copy, never the (possibly broken) new binary.
	if strings.Contains(u, `"/opt/sentinelgo/sentinelgo" `) {
		t.Errorf("unit runs the agent binary:\n%s", u)
	}
}

func TestLaunchdBootPlist(t *testing.T) {
	p, err := launchdBootPlist(bootMarker(), "/opt/sentinelgo/.sentinelgo/update_marker.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>com.sentinelgo.update-watchdog</string>",
		"<string>/opt/sentinelgo/sentinelgo-update-watchdog</string>",
		"<string>update-watchdog</string>",
		"<string>--boot</string>",
		"<key>RunAtLoad</key>\n    <true/>",
		"<key>KeepAlive</key>\n    <false/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q:\n%s", want, p)
		}
	}
}

func TestScheduledTaskXML(t *testing.T) {
	m := &Marker{WatchdogPath: `C:\SentinelGo\sentinelgo-update-watchdog.exe`}
	b, err := scheduledTaskXML(m, `C:\SentinelGo\.sentinelgo\update_marker.json`)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe || len(b)%2 != 0 {
		t.Fatal("not UTF-16LE with a BOM")
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 2; i < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	s := string(utf16.Decode(u))
	for _, want := range []string{
		"<BootTrigger>",
		"<UserId>S-1-5-18</UserId>",
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		`<Command>C:\SentinelGo\sentinelgo-update-watchdog.exe</Command>`,
		`<Arguments>update-watchdog --marker &#34;C:\SentinelGo\.sentinelgo\update_marker.json&#34; --boot</Arguments>`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("task XML lacks %q:\n%s", want, s)
		}
	}
}

func TestBootJobRejectsOddPaths(t *testing.T) {
	m := &Marker{WatchdogPath: `/opt/x"y/watchdog`}
	if _, err := systemdUnit(m, "/m.json"); err == nil {
		t.Error("systemd unit with a quote in the path")
	}
	if _, err := launchdBootPlist(&Marker{WatchdogPath: "/w"}, "/a%b/m.json"); err == nil {
		t.Error("plist with % in the marker path")
	}
	if _, err := scheduledTaskXML(&Marker{WatchdogPath: ""}, `C:\m.json`); err == nil {
		t.Error("task with an empty watchdog path")
	}
}

// ── When the boot job is registered and removed ─────────────────────────────

// An update registers the boot job next to the spawned watchdog.
func TestStartHealthWatch_RegistersBootJob(t *testing.T) {
	calls := resetBootCalls(t)
	stubSpawn(t)
	exe := fakeExecutable(t, []byte("old agent"))
	if err := os.WriteFile(exe+".backup", []byte("old agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &config.Config{Path: filepath.Join(dir, "config.json")}
	m, markerPath, err := startHealthWatch(cfg, "v1.0.0", "v2.0.0", "", exe+".backup")
	if err != nil {
		t.Fatal(err)
	}
	if reg, _ := calls(); len(reg) != 1 || reg[0] != markerPath {
		t.Fatalf("registered %v, want [%s]", reg, markerPath)
	}
	// The update not going ahead removes it again.
	endHealthWatch(m, markerPath)
	if _, un := calls(); un != 1 {
		t.Errorf("unregistered %d times after endHealthWatch, want 1", un)
	}
}

// No boot job without a running watchdog: a spawn failure refuses the update
// before anything is registered.
func TestStartHealthWatch_SpawnFailureRegistersNothing(t *testing.T) {
	calls := resetBootCalls(t)
	prev := spawnWatchdogFn
	spawnWatchdogFn = func(*Marker, string) error { return errors.New("no") }
	t.Cleanup(func() { spawnWatchdogFn = prev })
	exe := fakeExecutable(t, []byte("old agent"))
	if err := os.WriteFile(exe+".backup", []byte("old agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Path: filepath.Join(t.TempDir(), "config.json")}
	if _, _, err := startHealthWatch(cfg, "v1.0.0", "v2.0.0", "", exe+".backup"); err == nil {
		t.Fatal("update went ahead without a watchdog")
	}
	if reg, _ := calls(); len(reg) != 0 {
		t.Errorf("registered %v", reg)
	}
}

// The new binary registers it at each start too (an update started by a
// release without #516), and the confirmation removes it.
func TestStartHealthCheck_RegistersAndConfirmRemoves(t *testing.T) {
	calls := resetBootCalls(t)
	stubSpawn(t)
	cfg, markerPath, _ := healthSetup(t)
	StartHealthCheck(t.Context(), cfg)
	if reg, _ := calls(); len(reg) != 1 || reg[0] != markerPath {
		t.Fatalf("registered %v, want [%s]", reg, markerPath)
	}
	ConfirmHealthy(cfg)
	if _, un := calls(); un != 1 {
		t.Errorf("unregistered %d times after confirming, want 1", un)
	}
}

// The watchdog removes the boot job on every way out, except while an update
// is still pending (a failed rollback keeps marker and backup, so the next
// boot tries again).
func TestRetireBootIfDone_EveryExit(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, markerPath string, m *Marker, w *fakeWatchdog)
		remove bool
	}{
		{"confirmed healthy (marker gone)", func(t *testing.T, p string, _ *Marker, _ *fakeWatchdog) {
			_ = os.Remove(p)
		}, true},
		{"rolled back", func(t *testing.T, _ string, _ *Marker, w *fakeWatchdog) {
			w.now = w.now.Add(time.Hour) // past every deadline, never started
		}, true},
		{"marker invalid", func(t *testing.T, p string, m *Marker, _ *fakeWatchdog) {
			m.BackupPath = "/elsewhere"
			if err := writeJSONAtomic(p, m); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"marker unreadable", func(t *testing.T, p string, _ *Marker, w *fakeWatchdog) {
			if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"rollback failed, update still pending", func(t *testing.T, _ string, _ *Marker, w *fakeWatchdog) {
			w.now = w.now.Add(time.Hour)
			w.installErr = errors.New("locked")
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := resetBootCalls(t)
			markerPath, m, w := watchdogSetup(t, nil)
			c.setup(t, markerPath, m, w)
			runWatchdog(markerPath, w.deps())
			retireBootIfDone(markerPath)
			_, un := calls()
			if c.remove && un != 1 {
				t.Errorf("boot job kept (%d removals)", un)
			}
			if !c.remove && un != 0 {
				t.Errorf("boot job removed while the update is pending")
			}
		})
	}
}

// A marker kept only as the record of a rolled-back version (its backup is
// gone) isn't a pending update: the boot job must not try to roll it back
// again at every boot.
func TestUpdatePending_KeptMarkerWithoutBackup(t *testing.T) {
	markerPath, m, _ := watchdogSetup(t, nil)
	if !updatePending(markerPath) {
		t.Fatal("a fresh update isn't pending")
	}
	_ = os.Remove(m.BackupPath)
	if updatePending(markerPath) {
		t.Error("a marker without its backup is pending")
	}
}

// Retiring a stale marker in an update check removes the boot job.
func TestRetireExpired_RemovesBootJob(t *testing.T) {
	calls := resetBootCalls(t)
	cfg, markerPath, m := healthSetup(t)
	m.GiveUpAt = time.Now().Add(-time.Minute)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		t.Fatal(err)
	}
	if _, pending := pendingUpdate(cfg, time.Now()); pending {
		t.Fatal("stale marker still pending")
	}
	if _, un := calls(); un != 1 {
		t.Errorf("unregistered %d times, want 1", un)
	}
}

// ── The watchdog started at boot ────────────────────────────────────────────

// After a reboot near the deadline, a boot watchdog gives the new binary a
// full window from the boot (no rollback while it is still starting), and
// rolls back one that never records a start (it crashes before its health
// check, however often the service manager restarts it).
func TestBootWatchdog_SilentCrashLoopRolledBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	// Started before the reboot, 9 minutes into the window.
	setHealth(t, m, HealthState{Attempts: 1, BootedAt: w.now, AliveAt: w.now.Add(9 * time.Minute)})
	w.now = w.now.Add(12 * time.Minute) // rebooted: the marker's and that start's deadlines passed
	d := w.deps()
	d.bootAt = w.now
	bootAt := w.now
	code := runWatchdog(markerPath, d)
	assertRolledBack(t, markerPath, m, w, code, "didn't start after the reboot")
	if w.now.Before(bootAt.Add(HealthWindow)) {
		t.Errorf("rolled back %s after boot, before the window from boot ended", w.now.Sub(bootAt))
	}
}

// A new binary that does start after the reboot gets the normal treatment
// (its own fresh window), and confirming it ends the watchdog.
func TestBootWatchdog_StartedAfterRebootNotRolledBack(t *testing.T) {
	markerPath, m, w := watchdogSetup(t, nil)
	w.now = w.now.Add(12 * time.Minute)
	bootAt := w.now
	w.onSleep = func(n int) {
		switch n {
		case 6: // 30 s after boot the service starts and records it
			setHealth(t, m, HealthState{Attempts: 2, BootedAt: w.now, AliveAt: w.now})
		case 30: // and is confirmed healthy
			_ = os.Remove(markerPath)
		}
	}
	d := w.deps()
	d.bootAt = bootAt
	if code := runWatchdog(markerPath, d); code != 0 || w.installs != 0 {
		t.Fatalf("exit %d, installs %d; want no rollback", code, w.installs)
	}
}

func TestJudge_BootWindow(t *testing.T) {
	now := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	m := &Marker{Deadline: now.Add(-time.Hour), GiveUpAt: now.Add(time.Hour), MaxAttempts: 3}
	pre := HealthState{Attempts: 1, BootedAt: now.Add(-2 * time.Hour), AliveAt: now.Add(-90 * time.Minute)}
	if r, _ := judge(m, pre, now.Add(time.Minute), time.Time{}, now, nil); r != "" {
		t.Errorf("rolled back %s into the boot window: %s", time.Minute, r)
	}
	if r, _ := judge(m, pre, now.Add(HealthWindow+time.Second), time.Time{}, now, nil); !strings.Contains(r, "reboot") {
		t.Errorf("after the boot window: %q, want the no-start-after-reboot reason", r)
	}
	// Without bootAt (a watchdog spawned by an agent) nothing changes.
	if r, _ := judge(m, pre, now.Add(time.Minute), time.Time{}, time.Time{}, nil); r == "" {
		t.Error("a non-boot watchdog waited past the deadline")
	}
}

// ── Only one watchdog ───────────────────────────────────────────────────────

// A boot-started watchdog that finds one already running (the new binary's
// ensureWatchdog was first) exits without acting and leaves the boot job to
// the running one.
func TestRunWatchdog_BootSecondInstanceExits(t *testing.T) {
	calls := resetBootCalls(t)
	markerPath, m, _ := watchdogSetup(t, nil)
	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	if code := RunWatchdog(markerPath, true); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if got := mustReadFile(t, m.ExePath); string(got) != "broken new agent" {
		t.Errorf("second watchdog acted: %q", got)
	}
	if _, un := calls(); un != 0 {
		t.Error("the second watchdog removed the boot job")
	}
}

// And the other way round: while a boot-started watchdog holds the lock, the
// new binary doesn't start another.
func TestEnsureWatchdog_NoSecondWhileBootWatchdogRuns(t *testing.T) {
	spawned := stubSpawn(t)
	markerPath, m, _ := watchdogSetup(t, nil)
	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	ensureWatchdog(m, markerPath)
	if len(*spawned) != 0 {
		t.Errorf("spawned %v while a watchdog holds the lock", *spawned)
	}
}
