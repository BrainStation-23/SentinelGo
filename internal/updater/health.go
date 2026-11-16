package updater

// Update health check and rollback (#503).
//
// An upgrade keeps <exe>.backup until the new binary proves it works:
//
//  1. Before restarting, the old binary writes an update marker next to the
//     config (from/to version, paths, deadline) and starts a detached
//     watchdog: a copy of itself running `sentinelgo update-watchdog --marker
//     <path>`, outside the service so it survives the restart. The marker is
//     written once and only ever deleted after that.
//  2. Each start of the new binary records a boot attempt and its start time
//     in its own health file, and marks itself alive while it runs. If no
//     watchdog holds the watchdog lock (the device rebooted), it starts one.
//  3. The new binary is healthy once it is signed in and its first
//     agent-info RPC succeeded (ConfirmHealthy). It then deletes the marker,
//     its health file and the backup, and the watchdog exits.
//  4. If the binary started more than MaxAttempts times, or the deadline
//     (the marker's, or HealthWindow after the latest start) passes, the
//     watchdog puts the backup back, restarts the service and records the
//     version as bad, so the update checks skip it until the server offers
//     another version. A new binary that is running but can't reach the
//     server while the watchdog can't either is given more time (the network,
//     not the release, is down), up to GiveUpAt.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/sanitize"
)

// File names, next to config.json.
const (
	markerFileName   = "update_marker.json"
	healthFileName   = "update_health.json"
	rollbackFileName = "update_rollback.json"
	watchdogLockName = "update_watchdog.lock"
	WatchdogLogName  = "update_watchdog.log"
	// transitionLockName is held by whichever process ends the update: the
	// agent confirming it healthy or the watchdog rolling it back, so only
	// one of them completes.
	transitionLockName = "update_transition.lock"
	// rolledBackMarkerName is the marker renamed after a rollback whose
	// record couldn't be written (a full disk): a rename needs no new space,
	// and it still names the bad version.
	rolledBackMarkerName = "update_rolledback_marker.json"
)

// Health check timing. HealthWindow covers a restart, sign-in, the startup
// update check's jitter (up to 5 min, it runs before agent-info-update) and
// the agent-info collection (up to 90 s).
const (
	HealthWindow       = 10 * time.Minute
	MaxBootAttempts    = 3
	maxOfflineWait     = 24 * time.Hour
	aliveInterval      = 30 * time.Second
	aliveFresh         = 2 * time.Minute
	watchdogPoll       = 5 * time.Second
	watchdogReadErrMax = 60 // consecutive unreadable marker polls before giving up
	// How long each side waits for the transition lock. The agent retries a
	// confirmation from its alive ticker, so it waits briefly; the watchdog
	// retries at its next poll.
	confirmLockWait  = 2 * time.Second
	rollbackLockWait = 30 * time.Second
	lockRetry        = 100 * time.Millisecond
)

// Marker is the update in progress. The old binary writes it once; the new
// binary (healthy) or the watchdog (rollback) deletes it.
type Marker struct {
	FromVersion  string    `json:"from_version"`
	ToVersion    string    `json:"to_version"`
	ExePath      string    `json:"exe_path"`
	BackupPath   string    `json:"backup_path"`
	WatchdogPath string    `json:"watchdog_path,omitempty"`
	HealthPath   string    `json:"health_path"`
	RecordPath   string    `json:"rollback_record_path"`
	ProbeURL     string    `json:"probe_url,omitempty"`
	Created      time.Time `json:"created"`
	Deadline     time.Time `json:"deadline"`
	GiveUpAt     time.Time `json:"give_up_at"`
	MaxAttempts  int       `json:"max_attempts"`
}

// HealthState is written only by the new binary, so the agent and the
// watchdog never write the same file.
type HealthState struct {
	Version  string    `json:"version"`
	Attempts int       `json:"attempts"`
	BootedAt time.Time `json:"booted_at"`
	AliveAt  time.Time `json:"alive_at"`
}

// RollbackRecord is the version the watchdog rolled back from. The update
// checks skip BadVersion; the restored agent logs the rollback once.
type RollbackRecord struct {
	BadVersion      string    `json:"bad_version"`
	RestoredVersion string    `json:"restored_version"`
	Reason          string    `json:"reason"`
	At              time.Time `json:"at"`
	Logged          bool      `json:"logged"`
}

// This process's side of the health check. healthy: ConfirmHealthy saw the
// agent work; confirmed: the marker is gone, nothing left to do.
var (
	healthMu  sync.Mutex
	healthy   bool
	confirmed bool
	// watching: this binary is an upgrade whose alive ticker runs
	// (StartHealthCheck), so a confirmation can be retried from it.
	watching bool
)

// healthDir is where the marker and rollback record live: next to the config,
// or next to the binary when there is no config path.
func healthDir(cfg *config.Config) string {
	if cfg != nil && cfg.Path != "" {
		return filepath.Dir(cfg.Path)
	}
	if exe, err := executablePath(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func markerPathFor(cfg *config.Config) string { return filepath.Join(healthDir(cfg), markerFileName) }
func recordPathFor(cfg *config.Config) string { return filepath.Join(healthDir(cfg), rollbackFileName) }

// watchdogLockPath is the lock a running watchdog holds, next to its marker.
func watchdogLockPath(markerPath string) string {
	return filepath.Join(filepath.Dir(markerPath), watchdogLockName)
}

// transitionLockPath is the lock that confirm and rollback share.
func transitionLockPath(markerPath string) string {
	return filepath.Join(filepath.Dir(markerPath), transitionLockName)
}

// acquireTransition takes the transition lock, retrying for up to wait. The
// lock is an OS file lock, so it works across the agent and the watchdog.
func acquireTransition(markerPath string, wait time.Duration) (*lockfile.LockFile, error) {
	lock := lockfile.NewLockFileWithPath(transitionLockPath(markerPath))
	deadline := time.Now().Add(wait)
	for {
		err := lock.TryAcquire()
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, lockfile.ErrAlreadyRunning) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(lockRetry)
	}
}

// sameUpdate reports whether a and b describe the same update.
func sameUpdate(a, b *Marker) bool {
	return a.Created.Equal(b.Created) && a.FromVersion == b.FromVersion && a.ToVersion == b.ToVersion && a.ExePath == b.ExePath
}

// watchdogPathFor is the watchdog copy of the old binary, next to it. A
// separate copy because on Windows a running .exe can't be deleted, and the
// healthy new binary deletes the backup.
func watchdogPathFor(exe string) string {
	name := "sentinelgo-update-watchdog"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}

// writeJSONAtomic writes v to path through a temp file of its own and a
// rename, so a reader never sees a half-written file.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed names in the agent's config dir
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

// ReadMarker reads the marker at path; fs.ErrNotExist means no update is
// pending.
func ReadMarker(path string) (*Marker, error) {
	var m Marker
	if err := readJSON(path, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate rejects a marker that would copy anything but <exe>.backup over
// the binary.
func (m *Marker) validate() error {
	switch {
	case m.ExePath == "" || !filepath.IsAbs(m.ExePath):
		return fmt.Errorf("update marker: exe_path %q is not absolute", m.ExePath)
	case m.BackupPath != m.ExePath+".backup":
		return fmt.Errorf("update marker: backup_path %q is not %q", m.BackupPath, m.ExePath+".backup")
	case m.RecordPath == "" || !filepath.IsAbs(m.RecordPath):
		return fmt.Errorf("update marker: rollback_record_path %q is not absolute", m.RecordPath)
	case m.HealthPath == "" || !filepath.IsAbs(m.HealthPath):
		return fmt.Errorf("update marker: health_path %q is not absolute", m.HealthPath)
	}
	return nil
}

// beginHealthWatch writes the marker and the watchdog copy for an upgrade
// from running to `to`. On error nothing is left behind.
func beginHealthWatch(cfg *config.Config, running, to, backupPath string, now time.Time) (*Marker, string, error) {
	exe, err := executablePath()
	if err != nil {
		return nil, "", err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return nil, "", err
	}
	dir, err := filepath.Abs(healthDir(cfg))
	if err != nil {
		return nil, "", err
	}
	m := &Marker{
		FromVersion: running, ToVersion: to,
		ExePath: exe, BackupPath: backupPath,
		WatchdogPath: watchdogPathFor(exe),
		HealthPath:   filepath.Join(dir, healthFileName),
		RecordPath:   filepath.Join(dir, rollbackFileName),
		Created:      now.UTC(), Deadline: now.Add(HealthWindow).UTC(), GiveUpAt: now.Add(maxOfflineWait).UTC(),
		MaxAttempts: MaxBootAttempts,
	}
	if cfg != nil {
		m.ProbeURL = cfg.SupabaseURL
	}
	if err := m.validate(); err != nil {
		return nil, "", err
	}
	if err := copyFile(backupPath, m.WatchdogPath); err != nil {
		_ = os.Remove(m.WatchdogPath)
		return nil, "", fmt.Errorf("copy the watchdog: %w", err)
	}
	// Only the service account runs the watchdog.
	_ = os.Chmod(m.WatchdogPath, 0o700)
	_ = os.Remove(m.HealthPath) // from an earlier update
	markerPath := filepath.Join(dir, markerFileName)
	if err := writeJSONAtomic(markerPath, m); err != nil {
		_ = os.Remove(m.WatchdogPath)
		return nil, "", fmt.Errorf("write the update marker: %w", err)
	}
	return m, markerPath, nil
}

// endHealthWatch removes what beginHealthWatch wrote (an update that didn't
// go ahead).
func endHealthWatch(m *Marker, markerPath string) {
	_ = os.Remove(markerPath)
	_ = os.Remove(m.WatchdogPath)
}

// pendingUpdate reports whether an earlier update is still waiting to be
// confirmed healthy (or rolled back). A marker past GiveUpAt is stale (its
// watchdog is gone) and is removed.
func pendingUpdate(cfg *config.Config, now time.Time) (*Marker, bool) {
	path := markerPathFor(cfg)
	m, err := ReadMarker(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		log.Printf("Updater: unreadable update marker, removing it: %v", err)
		_ = os.Remove(path)
		return nil, false
	}
	if now.After(m.GiveUpAt) {
		return retireExpired(path, m)
	}
	return m, true
}

// retireExpired handles a marker past GiveUpAt, holding the transition lock
// so it can't race a watchdog that is rolling the same update back (which
// would then delete a newer update's files). It reports pending (no update
// now) while the lock is busy, the marker changed, or the marker is the
// only record of a version that must stay blocked.
func retireExpired(path string, m *Marker) (*Marker, bool) {
	lock, err := acquireTransition(path, confirmLockWait)
	if err != nil {
		log.Printf("Updater: the update watchdog is busy; not updating yet: %v", err)
		return m, true
	}
	defer func() { _ = lock.Release() }()
	cur, err := ReadMarker(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil || !sameUpdate(cur, m) {
		return m, true // changed meanwhile: decide on the next check
	}
	_ = os.Remove(m.HealthPath)
	if !sameVersion(m.ToVersion, config.Version) {
		// The update isn't what runs: the watchdog rolled it back but
		// couldn't save the record or rename the marker, or the update
		// never stayed installed. Keep blocking that version: move the
		// marker to the rolled-back name (freeing the slot for the next
		// update), or leave it where it is if even that fails.
		log.Printf("Updater: %s didn't stay installed; it stays blocked on this device", sanitize.ForLog(m.ToVersion))
		if err := os.Rename(path, filepath.Join(filepath.Dir(path), rolledBackMarkerName)); err != nil {
			// The marker is the only record of the bad version: a new
			// update would overwrite it, so no update until it moves.
			log.Printf("Updater: keeping the update marker so %s isn't installed again; updates wait until it can be moved: %v", sanitize.ForLog(m.ToVersion), err)
			return m, true
		}
		return nil, false
	}
	log.Printf("Updater: removing a stale update marker (%s -> %s)", sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
	_ = os.Remove(path)
	return nil, false
}

// rolledBackVersions are the versions this device must not install again:
// the rollback record's, the renamed marker's (a rollback whose record
// couldn't be written), and a marker left in place past GiveUpAt whose
// version isn't the one running. All of them count, so an older record
// can't hide a newer failure.
func rolledBackVersions(cfg *config.Config, now time.Time) []string {
	var out []string
	var r RollbackRecord
	if readJSON(recordPathFor(cfg), &r) == nil && r.BadVersion != "" {
		out = append(out, r.BadVersion)
	}
	var m Marker
	if readJSON(filepath.Join(healthDir(cfg), rolledBackMarkerName), &m) == nil && m.ToVersion != "" {
		out = append(out, m.ToVersion)
	}
	var kept Marker
	if readJSON(markerPathFor(cfg), &kept) == nil && kept.ToVersion != "" &&
		now.After(kept.GiveUpAt) && !sameVersion(kept.ToVersion, config.Version) {
		out = append(out, kept.ToVersion)
	}
	return out
}

// rolledBack reports whether version is one of rolledBackVersions.
func rolledBack(cfg *config.Config, version string, now time.Time) bool {
	for _, bad := range rolledBackVersions(cfg, now) {
		if sameVersion(bad, version) {
			return true
		}
	}
	return false
}

// StartHealthCheck runs at agent startup. It logs a rollback the watchdog did
// (once). When this binary is an upgrade still waiting for its health check,
// it records the start, makes sure a watchdog runs (none survives a reboot),
// and keeps marking itself alive, and retrying a failed confirmation, until
// the check is done or ctx ends.
func StartHealthCheck(ctx context.Context, cfg *config.Config) {
	logRollback(cfg)

	path := markerPathFor(cfg)
	m, err := ReadMarker(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No update pending: remove a watchdog copy left behind
			// (Windows can't delete it while it still runs).
			if exe, e := executablePath(); e == nil {
				_ = os.Remove(watchdogPathFor(exe))
			}
		}
		return
	}
	if !sameVersion(m.ToVersion, config.Version) {
		return // the old binary: the watchdog handles it
	}

	healthMu.Lock()
	var h HealthState
	if readJSON(m.HealthPath, &h) != nil || !sameVersion(h.Version, config.Version) {
		h = HealthState{Version: config.Version}
	}
	now := time.Now().UTC()
	h.Attempts++
	h.BootedAt, h.AliveAt = now, now
	if err := writeJSONAtomic(m.HealthPath, h); err != nil {
		log.Printf("Updater: can't record this start for the update health check: %v", err)
	}
	watching = true
	healthMu.Unlock()
	log.Printf("Updater: running %s after an update from %s (start %d of %d); waiting for sign-in and the first agent-info upload",
		sanitize.ForLog(m.ToVersion), sanitize.ForLog(m.FromVersion), h.Attempts, m.MaxAttempts)

	ensureWatchdog(m, path)

	go func() {
		t := time.NewTicker(aliveInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !healthTick(m) {
					return
				}
			}
		}
	}()
}

// ensureWatchdog starts a watchdog unless one holds the watchdog lock.
func ensureWatchdog(m *Marker, markerPath string) {
	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		return // one is running (or the lock can't be taken: don't start a second)
	}
	_ = lock.Release()
	if err := spawnWatchdogFn(m, markerPath); err != nil {
		log.Printf("Updater: can't start the update watchdog: %v", err)
		return
	}
	log.Printf("Updater: started the update watchdog (none was running)")
}

// healthTick marks the binary alive, or finishes a confirmation that failed
// earlier; false once there is nothing left to do.
func healthTick(m *Marker) bool {
	healthMu.Lock()
	defer healthMu.Unlock()
	if confirmed {
		return false
	}
	if healthy {
		return !finishConfirm(m)
	}
	var h HealthState
	if readJSON(m.HealthPath, &h) != nil || !sameVersion(h.Version, config.Version) {
		h = HealthState{Version: config.Version, Attempts: 1, BootedAt: time.Now().UTC()}
	}
	h.AliveAt = time.Now().UTC()
	if err := writeJSONAtomic(m.HealthPath, h); err != nil {
		log.Printf("Updater: can't refresh the update health file: %v", err)
	}
	return true
}

// ConfirmHealthy is called after the agent signed in and an agent-info RPC
// succeeded. If this binary is an upgrade waiting for that, it deletes the
// marker, its health file and the backup, so the watchdog exits without
// rolling back. A failed deletion is retried from the alive ticker.
func ConfirmHealthy(cfg *config.Config) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if confirmed {
		return
	}
	m, err := ReadMarker(markerPathFor(cfg))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			confirmed = true
			return
		}
		if watching {
			// A transient read error (e.g. a Windows sharing violation):
			// the agent is healthy, so let the alive ticker finish the
			// confirmation (finishConfirm re-reads the marker) before the
			// watchdog's deadline, instead of waiting for the next upload.
			log.Printf("Updater: can't read the update marker to confirm the update (will retry): %v", err)
			healthy = true
		}
		return
	}
	if !sameVersion(m.ToVersion, config.Version) {
		return
	}
	healthy = true
	finishConfirm(m)
}

// finishConfirm deletes the update's files; true once there is nothing left
// to do. Called with healthMu held. It holds the transition lock, so a
// watchdog can't roll the same update back while it runs; if the watchdog
// already did (the marker is gone or is another update's), it leaves
// everything alone.
func finishConfirm(m *Marker) bool {
	markerPath := filepath.Join(filepath.Dir(m.HealthPath), markerFileName)
	lock, err := acquireTransition(markerPath, confirmLockWait)
	if err != nil {
		log.Printf("Updater: the update watchdog is busy; confirming later: %v", err)
		return false
	}
	defer func() { _ = lock.Release() }()
	cur, err := ReadMarker(markerPath)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !sameUpdate(cur, m)) {
		log.Printf("Updater: update %s -> %s was already ended by the watchdog; nothing to confirm",
			sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
		confirmed = true
		return true
	}
	if err != nil {
		log.Printf("Updater: can't read the update marker (will retry): %v", err)
		return false
	}
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("Updater: can't remove the update marker (will retry): %v", err)
		return false
	}
	confirmed = true
	_ = os.Remove(m.HealthPath)
	if m.validate() == nil {
		_ = os.Remove(m.BackupPath)
	}
	_ = os.Remove(m.WatchdogPath) // fails on Windows while it still runs; removed at the next start
	log.Printf("Updater: update %s -> %s is healthy; backup removed", sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
	return true
}

// logRollback logs a rollback once, so it shows in the uploaded agent log.
func logRollback(cfg *config.Config) {
	path := recordPathFor(cfg)
	var r RollbackRecord
	if readJSON(path, &r) != nil || r.Logged {
		return
	}
	log.Printf("Updater: UPDATE ROLLED BACK at %s: %s -> %s (%s). %s is skipped until the server offers another version.",
		r.At.Format(time.RFC3339), sanitize.ForLog(r.BadVersion), sanitize.ForLog(r.RestoredVersion),
		sanitize.ForLog(r.Reason), sanitize.ForLog(r.BadVersion))
	r.Logged = true
	if err := writeJSONAtomic(path, r); err != nil {
		log.Printf("Updater: can't update the rollback record: %v", err)
	}
}

// ── Watchdog ────────────────────────────────────────────────────────────────

// watchdogDeps are the watchdog's side effects, swapped in tests.
type watchdogDeps struct {
	now       func() time.Time
	sleep     func(time.Duration)
	networkUp func(probeURL string) bool
	// install puts the backup in place of the binary, stopping the service
	// first where the OS needs that (Windows).
	install func(m *Marker) error
	// restart starts the service again with the restored binary.
	restart func() error
	// start starts the service if it isn't running (a no-op error if it is).
	start func() error
	// lock takes the transition lock; nil release when it can't.
	lock func(markerPath string) (release func(), err error)
}

func defaultWatchdogDeps() watchdogDeps {
	return watchdogDeps{
		now: time.Now, sleep: time.Sleep,
		networkUp: func(u string) bool { return CheckInternetWithHTTP(u) },
		install:   installBackup,
		restart:   restartService,
		start:     startService,
		lock: func(markerPath string) (func(), error) {
			l, err := acquireTransition(markerPath, rollbackLockWait)
			if err != nil {
				return nil, err
			}
			return func() { _ = l.Release() }, nil
		},
	}
}

// RunWatchdog watches the marker at markerPath until the update is confirmed
// healthy (the marker is gone) or rolls it back. It returns a process exit
// code.
func RunWatchdog(markerPath string) int {
	lock := lockfile.NewLockFileWithPath(watchdogLockPath(markerPath))
	if err := lock.TryAcquire(); err != nil {
		log.Printf("Update watchdog: another watchdog is running (%v); exiting", err)
		return 0
	}
	defer func() { _ = lock.Release() }()
	return runWatchdog(markerPath, defaultWatchdogDeps())
}

func runWatchdog(markerPath string, d watchdogDeps) int {
	log.Printf("Update watchdog: watching %s", markerPath)
	readErrs := 0
	var extendedUntil time.Time // offline extensions, kept here: the marker isn't rewritten
	for {
		m, err := ReadMarker(markerPath)
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("Update watchdog: no update pending (confirmed healthy); exiting")
			return 0
		}
		if err != nil {
			// The agent may be mid-rename (Windows sharing violation).
			if readErrs++; readErrs >= watchdogReadErrMax {
				log.Printf("Update watchdog: giving up, marker unreadable: %v", err)
				return 1
			}
			d.sleep(watchdogPoll)
			continue
		}
		readErrs = 0
		if err := m.validate(); err != nil {
			log.Printf("Update watchdog: %v; not acting on it", err)
			return 1
		}
		now := d.now()
		reason, offline := judge(m, readHealthState(m), now, extendedUntil, d.networkUp)
		if offline {
			log.Printf("Update watchdog: %s is running but the server is unreachable from here too; waiting longer", sanitize.ForLog(m.ToVersion))
			extendedUntil = now.Add(HealthWindow)
		}
		if reason == "" {
			d.sleep(watchdogPoll)
			continue
		}
		// Roll back only while holding the transition lock, and only if the
		// agent didn't confirm this update healthy in the meantime.
		release, err := d.lock(markerPath)
		if err != nil {
			log.Printf("Update watchdog: the agent is confirming the update; checking again: %v", err)
			d.sleep(watchdogPoll)
			continue
		}
		cur, err := ReadMarker(markerPath)
		if errors.Is(err, fs.ErrNotExist) {
			release()
			log.Printf("Update watchdog: the update was confirmed healthy just now; exiting")
			return 0
		}
		if err != nil || !sameUpdate(cur, m) {
			release()
			d.sleep(watchdogPoll)
			continue
		}
		// Decide again on what the new binary wrote up to now: one that
		// started after the deadline and before the lock was taken gets its
		// fresh health window.
		if reason, _ = judge(cur, readHealthState(cur), d.now(), extendedUntil, d.networkUp); reason == "" {
			release()
			d.sleep(watchdogPoll)
			continue
		}
		return rollBack(markerPath, m, reason, d, release)
	}
}

// readHealthState is the new binary's health file, or zero when it is
// missing or for another version.
func readHealthState(m *Marker) HealthState {
	var h HealthState
	if readJSON(m.HealthPath, &h) != nil || !sameVersion(h.Version, m.ToVersion) {
		return HealthState{}
	}
	return h
}

// judge returns why the update must be rolled back now ("" to keep
// waiting), and whether to wait longer because the network is down.
func judge(m *Marker, h HealthState, now, extendedUntil time.Time, networkUp func(string) bool) (reason string, offline bool) {
	if m.MaxAttempts > 0 && h.Attempts > m.MaxAttempts {
		return fmt.Sprintf("started %d times without becoming healthy", h.Attempts), false
	}
	deadline := m.Deadline
	if !h.BootedAt.IsZero() && h.BootedAt.Add(HealthWindow).After(deadline) {
		deadline = h.BootedAt.Add(HealthWindow) // a fresh window per start (e.g. after a reboot)
	}
	if extendedUntil.After(deadline) {
		deadline = extendedUntil
	}
	if !now.After(deadline) {
		return "", false
	}
	alive := !h.AliveAt.IsZero() && now.Sub(h.AliveAt) < aliveFresh
	if !alive {
		return "not running and not healthy within the health window", false
	}
	if now.Before(m.GiveUpAt) && m.ProbeURL != "" && !networkUp(m.ProbeURL) {
		return "", true
	}
	return "running but not signed in with a successful agent-info upload within the health window", false
}

// rollBack restores the backup, records the bad version and restarts the
// service. It is called holding the transition lock and calls release
// before starting the service, so the restored agent never waits on it.
func rollBack(markerPath string, m *Marker, reason string, d watchdogDeps, release func()) int {
	var once sync.Once
	unlock := func() { once.Do(release) }
	defer unlock()
	if same, err := sameContent(m.BackupPath, m.ExePath); err == nil && same {
		// The update never got installed (e.g. the Windows swap didn't run):
		// nothing to roll back, and the version isn't known to be bad. The
		// agent may not be running at all (the Windows update script starts
		// it only after a successful swap), so start it.
		log.Printf("Update watchdog: %s was never installed; cleaning up", sanitize.ForLog(m.ToVersion))
		_ = os.Remove(markerPath)
		_ = os.Remove(m.HealthPath)
		_ = os.Remove(m.BackupPath)
		unlock()
		if err := d.start(); err != nil {
			log.Printf("Update watchdog: starting the service: %v (fine if it is already running)", err)
		}
		return 0
	}
	log.Printf("Update watchdog: ROLLING BACK %s -> %s: %s", sanitize.ForLog(m.ToVersion), sanitize.ForLog(m.FromVersion), reason)
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if err = d.install(m); err == nil {
			break
		}
		log.Printf("Update watchdog: restoring the backup failed (attempt %d/3): %v", attempt, err)
		d.sleep(10 * time.Second)
	}
	if err != nil {
		log.Printf("Update watchdog: rollback failed; backup kept at %s", m.BackupPath)
		unlock()
		_ = d.restart()
		return 1
	}
	rec := RollbackRecord{BadVersion: m.ToVersion, RestoredVersion: m.FromVersion, Reason: reason, At: d.now().UTC()}
	if err := writeJSONAtomic(m.RecordPath, rec); err != nil {
		// The record is what keeps the update checks from installing the
		// bad version again. Without it, keep that guard: rename the marker
		// (no new disk space needed), or keep it in place as a last resort.
		log.Printf("Update watchdog: can't write the rollback record: %v", err)
		if rerr := os.Rename(markerPath, filepath.Join(filepath.Dir(markerPath), rolledBackMarkerName)); rerr != nil {
			log.Printf("Update watchdog: keeping the update marker so %s isn't installed again: %v", sanitize.ForLog(m.ToVersion), rerr)
		}
	} else {
		_ = os.Remove(markerPath)
	}
	_ = os.Remove(m.HealthPath)
	_ = os.Remove(m.BackupPath)
	unlock()
	if err := d.restart(); err != nil {
		log.Printf("Update watchdog: restarting the service failed: %v", err)
		return 1
	}
	log.Printf("Update watchdog: rolled back to %s", sanitize.ForLog(m.FromVersion))
	return 0
}

// sameContent reports whether two files have the same SHA-256.
func sameContent(a, b string) (bool, error) {
	ha, err := fileSHA256(a)
	if err != nil {
		return false, err
	}
	hb, err := fileSHA256(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ha, hb), nil
}

func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- paths from a validated marker
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// replaceWithBackup copies the backup over the binary through a temp file and
// a rename (Linux, macOS: the running file can be replaced).
func replaceWithBackup(m *Marker) error {
	info, err := os.Stat(m.BackupPath)
	if err != nil {
		return err
	}
	tmp := m.ExePath + ".rollback"
	if err := copyFile(m.BackupPath, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The backup has the binary's original mode (createBackup copies it).
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.ExePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
