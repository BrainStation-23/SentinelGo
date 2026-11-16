package updater

// Update health check and rollback (#503).
//
// A self-update keeps <exe>.backup until the new binary proves it works:
//
//  1. Before restarting, the old binary writes an update marker next to the
//     config (from/to version, backup path, deadline, boot attempts) and
//     starts a detached watchdog: a copy of itself running
//     `sentinelgo update-watchdog --marker <path>`, outside the service so
//     it survives the restart.
//  2. Each start of the new binary counts a boot attempt in the marker and
//     keeps marking itself alive while it runs.
//  3. The new binary is healthy once it is signed in and its first
//     agent-info RPC succeeded (ConfirmHealthy). It then deletes the marker
//     and the backup, and the watchdog exits.
//  4. If the deadline passes, or the binary has started more than
//     MaxAttempts times, the watchdog puts the backup back, restarts the
//     service and records the version as bad, so the update checks skip it
//     until the server offers another version. A new binary that is running
//     but can't reach the server while the watchdog can't either is given
//     more time (the network, not the release, is down), up to GiveUpAt.

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
	"sentinelgo/internal/sanitize"
)

// File names, next to config.json.
const (
	markerFileName   = "update_marker.json"
	rollbackFileName = "update_rollback.json"
	watchdogLogName  = "update_watchdog.log"
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
)

// Marker is the update in progress, shared by the agent and the watchdog.
type Marker struct {
	FromVersion  string    `json:"from_version"`
	ToVersion    string    `json:"to_version"`
	ExePath      string    `json:"exe_path"`
	BackupPath   string    `json:"backup_path"`
	WatchdogPath string    `json:"watchdog_path,omitempty"`
	RecordPath   string    `json:"rollback_record_path"`
	ProbeURL     string    `json:"probe_url,omitempty"`
	Created      time.Time `json:"created"`
	Deadline     time.Time `json:"deadline"`
	GiveUpAt     time.Time `json:"give_up_at"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	AliveAt      time.Time `json:"alive_at,omitzero"`
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

// healthMu serialises this process's marker writes (boot count, alive ticks,
// confirmation).
var (
	healthMu  sync.Mutex
	confirmed bool
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

// writeJSONAtomic writes v to path through a temp file and a rename, so a
// reader never sees a half-written file.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ReadMarker reads the marker at path; fs.ErrNotExist means no update is
// pending.
func ReadMarker(path string) (*Marker, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed name in the agent's config dir
	if err != nil {
		return nil, err
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("update marker: %w", err)
	}
	return &m, nil
}

func readRollbackRecord(path string) (*RollbackRecord, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed name in the agent's config dir
	if err != nil {
		return nil, err
	}
	var r RollbackRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("rollback record: %w", err)
	}
	return &r, nil
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
	}
	return nil
}

// beginHealthWatch writes the marker and the watchdog copy for an update from
// running to latest. On error nothing is left behind.
func beginHealthWatch(cfg *config.Config, running, to, backupPath string, now time.Time) (*Marker, string, error) {
	exe, err := executablePath()
	if err != nil {
		return nil, "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return nil, "", err
	}
	recordPath, err := filepath.Abs(recordPathFor(cfg))
	if err != nil {
		return nil, "", err
	}
	m := &Marker{
		FromVersion: running, ToVersion: to,
		ExePath: exe, BackupPath: backupPath,
		WatchdogPath: watchdogPathFor(exe),
		RecordPath:   recordPath,
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
	// #nosec G302 -- the watchdog is an executable copy of the agent
	_ = os.Chmod(m.WatchdogPath, 0o755)
	markerPath := markerPathFor(cfg)
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
		log.Printf("Updater: removing a stale update marker (%s -> %s)", sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
		_ = os.Remove(path)
		return nil, false
	}
	return m, true
}

// rolledBackVersion is the version this device rolled back from, or "".
func rolledBackVersion(cfg *config.Config) string {
	r, err := readRollbackRecord(recordPathFor(cfg))
	if err != nil {
		return ""
	}
	return r.BadVersion
}

// StartHealthCheck runs at agent startup. It logs a rollback the watchdog
// did (once), and when this binary is an update still waiting for its health
// check, counts the boot attempt and keeps marking it alive until
// ConfirmHealthy or ctx ends.
func StartHealthCheck(ctx context.Context, cfg *config.Config) {
	logRollback(cfg)

	healthMu.Lock()
	path := markerPathFor(cfg)
	m, err := ReadMarker(path)
	if err != nil || m.ToVersion != config.Version {
		healthMu.Unlock()
		if errors.Is(err, fs.ErrNotExist) {
			// No update pending: remove a watchdog copy left behind
			// (Windows can't delete it while it still runs).
			if exe, e := executablePath(); e == nil {
				_ = os.Remove(watchdogPathFor(exe))
			}
		}
		return
	}
	m.Attempts++
	m.AliveAt = time.Now().UTC()
	if err := writeJSONAtomic(path, m); err != nil {
		log.Printf("Updater: can't record boot attempt in the update marker: %v", err)
	}
	log.Printf("Updater: running %s after an update from %s (start %d of %d); waiting for sign-in and the first agent-info upload before %s",
		sanitize.ForLog(m.ToVersion), sanitize.ForLog(m.FromVersion), m.Attempts, m.MaxAttempts, m.Deadline.Format(time.RFC3339))
	healthMu.Unlock()

	go func() {
		t := time.NewTicker(aliveInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !touchAlive(path) {
					return
				}
			}
		}
	}()
}

// touchAlive refreshes AliveAt; false once there is nothing left to watch.
func touchAlive(path string) bool {
	healthMu.Lock()
	defer healthMu.Unlock()
	if confirmed {
		return false
	}
	m, err := ReadMarker(path)
	if err != nil || m.ToVersion != config.Version {
		return !errors.Is(err, fs.ErrNotExist) && err != nil
	}
	m.AliveAt = time.Now().UTC()
	if err := writeJSONAtomic(path, m); err != nil {
		log.Printf("Updater: can't refresh the update marker: %v", err)
	}
	return true
}

// ConfirmHealthy is called after the agent signed in and an agent-info RPC
// succeeded. If this binary is an update waiting for that, it deletes the
// marker and the backup, so the watchdog exits without rolling back.
func ConfirmHealthy(cfg *config.Config) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if confirmed {
		return
	}
	path := markerPathFor(cfg)
	m, err := ReadMarker(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			confirmed = true
		}
		return
	}
	if m.ToVersion != config.Version {
		return
	}
	confirmed = true
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("Updater: can't remove the update marker: %v", err)
		return
	}
	if m.validate() == nil {
		_ = os.Remove(m.BackupPath)
	}
	_ = os.Remove(m.WatchdogPath) // fails on Windows while it still runs; removed at the next start
	log.Printf("Updater: update %s -> %s is healthy; backup removed", sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
}

// logRollback logs a rollback once, so it shows in the uploaded agent log.
func logRollback(cfg *config.Config) {
	path := recordPathFor(cfg)
	r, err := readRollbackRecord(path)
	if err != nil || r.Logged {
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
}

func defaultWatchdogDeps() watchdogDeps {
	return watchdogDeps{
		now: time.Now, sleep: time.Sleep,
		networkUp: func(u string) bool { return CheckInternetWithHTTP(u) },
		install:   installBackup,
		restart:   restartService,
	}
}

// RunWatchdog watches the marker at markerPath until the update is confirmed
// healthy (the marker is gone) or rolls it back. It returns a process exit
// code.
func RunWatchdog(markerPath string) int {
	return runWatchdog(markerPath, defaultWatchdogDeps())
}

func runWatchdog(markerPath string, d watchdogDeps) int {
	log.Printf("Update watchdog: watching %s", markerPath)
	readErrs := 0
	for {
		m, err := ReadMarker(markerPath)
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("Update watchdog: update confirmed healthy; exiting")
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
		reason := ""
		switch {
		case m.MaxAttempts > 0 && m.Attempts > m.MaxAttempts:
			reason = fmt.Sprintf("started %d times without becoming healthy", m.Attempts)
		case now.After(m.Deadline):
			alive := !m.AliveAt.IsZero() && now.Sub(m.AliveAt) < aliveFresh
			if alive && now.Before(m.GiveUpAt) && m.ProbeURL != "" && !d.networkUp(m.ProbeURL) {
				log.Printf("Update watchdog: %s is running but the server is unreachable from here too; waiting longer", sanitize.ForLog(m.ToVersion))
				m.Deadline = now.Add(HealthWindow).UTC()
				if err := writeJSONAtomic(markerPath, m); err != nil {
					log.Printf("Update watchdog: can't extend the deadline: %v", err)
				}
				d.sleep(watchdogPoll)
				continue
			}
			if alive {
				reason = "running but not signed in with a successful agent-info upload within the health window"
			} else {
				reason = "not running and not healthy within the health window"
			}
		}
		if reason == "" {
			d.sleep(watchdogPoll)
			continue
		}
		return rollBack(markerPath, m, reason, d)
	}
}

// rollBack restores the backup, records the bad version and restarts the
// service.
func rollBack(markerPath string, m *Marker, reason string, d watchdogDeps) int {
	if same, err := sameContent(m.BackupPath, m.ExePath); err == nil && same {
		// The update never got installed (e.g. the Windows swap didn't run):
		// nothing to roll back, and the version isn't known to be bad.
		log.Printf("Update watchdog: %s was never installed; cleaning up", sanitize.ForLog(m.ToVersion))
		_ = os.Remove(markerPath)
		_ = os.Remove(m.BackupPath)
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
		_ = d.restart()
		return 1
	}
	rec := RollbackRecord{BadVersion: m.ToVersion, RestoredVersion: m.FromVersion, Reason: reason, At: d.now().UTC()}
	if err := writeJSONAtomic(m.RecordPath, rec); err != nil {
		log.Printf("Update watchdog: can't write the rollback record: %v", err)
	}
	_ = os.Remove(markerPath)
	_ = os.Remove(m.BackupPath)
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
	tmp := m.ExePath + ".rollback"
	if err := copyFile(m.BackupPath, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// #nosec G302 -- the agent binary must be executable
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.ExePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
