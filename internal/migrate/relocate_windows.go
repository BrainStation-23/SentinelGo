//go:build windows

package migrate

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/paths"
	"sentinelgo/internal/winsec"
)

// probeTimeout bounds the pre-flight execution check of the copied binary.
const probeTimeout = 30 * time.Second

// Run relocates a legacy C:\SentinelGo installation to the current layout.
//
// It is safe to call on every start: when there is nothing to migrate it returns
// immediately. The caller must invoke it before acquiring the process lock and
// before any subsystem starts, which is what guarantees no update can be in
// flight while files are moving.
//
// Ordering is deliberate throughout. Destinations are created and hardened
// before anything is written into them, so no file is ever briefly readable in a
// directory that still inherits from %ProgramData%. The copied binary is proven
// to execute before the service is repointed at it. The legacy tree is hardened
// rather than deleted, because the running binary lives in it and cannot delete
// itself.
func Run() Result {
	legacyDir := paths.LegacyInstallDir()
	if legacyDir == "" {
		return Result{Reason: "platform has no legacy layout"}
	}

	if markerExists(paths.DataDir()) {
		return Result{Reason: "already migrated"}
	}

	if !needsMigration(legacyDir) {
		return Result{Reason: "not running from the legacy location"}
	}

	log.Printf("Migration: relocating installation from %s to %s (state: %s)",
		legacyDir, paths.InstallDir(), paths.DataDir())

	result, err := relocate(legacyDir)
	if err != nil {
		// Abandoning a migration is safe: the legacy installation keeps running.
		// Crash-looping a fleet because a copy failed is not.
		log.Printf("Migration: abandoned, continuing from the existing location: %v", err)
		emergencylog.Record("migration", "relocation abandoned, agent continues at %s: %v",
			legacyDir, err)
		return Result{Reason: fmt.Sprintf("abandoned: %v", err)}
	}
	return result
}

// needsMigration reports whether this process is running out of the legacy tree.
func needsMigration(legacyDir string) bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		resolved = exePath
	}
	rel, err := filepath.Rel(legacyDir, resolved)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// relocate performs the migration, returning an error if any step fails.
func relocate(legacyDir string) (Result, error) {
	exePath, err := os.Executable()
	if err != nil {
		return Result{}, fmt.Errorf("resolve running binary: %w", err)
	}

	installDir := paths.InstallDir()
	dataDir := paths.DataDir()

	if err := prepareDir(installDir); err != nil {
		return Result{}, err
	}
	if err := prepareDir(dataDir); err != nil {
		return Result{}, err
	}

	// Copy the binary and verify it arrived intact.
	newExe := filepath.Join(installDir, filepath.Base(exePath))
	if err := os.Remove(newExe); err != nil && !os.IsNotExist(err) {
		return Result{}, fmt.Errorf("clear destination binary: %w", err)
	}
	if err := copyVerified(exePath, newExe); err != nil {
		return Result{}, err
	}
	if err := winsec.SecureSystemPath(newExe); err != nil {
		return Result{}, fmt.Errorf("secure relocated binary: %w", err)
	}

	// Prove the copy actually runs BEFORE repointing the service at it. This is
	// the single check standing between a bad copy -- truncated, quarantined by
	// AV, blocked by an execution policy -- and a fleet of services that exit
	// immediately and exhaust their restart actions with no agent left to fix it.
	if err := probeBinary(newExe); err != nil {
		_ = os.Remove(newExe)
		return Result{}, fmt.Errorf("relocated binary failed its pre-flight check: %w", err)
	}

	copyState(legacyDir, dataDir)

	newConfig := filepath.Join(dataDir, "config.json")
	if err := repointService(newExe, newConfig); err != nil {
		return Result{}, fmt.Errorf("repoint service: %w", err)
	}

	if err := writeMarker(dataDir, legacyDir, installDir, config.Version); err != nil {
		log.Printf("Migration: could not write completion marker: %v", err)
	}

	// Harden rather than delete. The running binary is inside this tree, so it
	// cannot be removed yet -- and leaving it writable would preserve the exact
	// staging ground the migration exists to eliminate.
	if err := winsec.SecureSystemTree(legacyDir); err != nil {
		log.Printf("Migration: could not secure the legacy directory %s: %v", legacyDir, err)
	}
	writeBreadcrumb(legacyDir, installDir, dataDir)

	log.Printf("Migration: complete. Binary %s, state %s. Exiting so the service "+
		"manager restarts from the new location.", newExe, dataDir)
	emergencylog.Record("migration", "relocated from %s to %s", legacyDir, installDir)

	return Result{Migrated: true, RestartRequired: true}, nil
}

// prepareDir creates a destination directory and hardens it before any content
// is written into it.
//
// A pre-existing destination is inspected rather than trusted. %ProgramData% is
// writable enough for a standard user to create a subdirectory ahead of us, and
// a reparse point there would redirect everything we then write -- including the
// agent's credentials -- somewhere of their choosing.
func prepareDir(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		audit, auditErr := winsec.AuditPath(dir)
		if auditErr != nil {
			return fmt.Errorf("audit existing directory %s: %w", dir, auditErr)
		}
		if audit.ReparsePoint {
			return fmt.Errorf("%s is a reparse point; refusing to migrate into a "+
				"redirected location", dir)
		}
	} else if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	if err := winsec.SecureSystemPath(dir); err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	return nil
}

// probeBinary runs the copied binary with -version and checks it reports the
// version this process was built as.
func probeBinary(exePath string) error {
	ctx, cancel := contextWithTimeout(probeTimeout)
	defer cancel()

	// #nosec G204 - exePath is a path this process just wrote into a directory
	// it secured moments earlier.
	out, err := exec.CommandContext(ctx, exePath, "-version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s -version: %w (output: %s)", exePath, err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), config.Version) {
		return fmt.Errorf("version mismatch: expected %q in output %q",
			config.Version, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyState copies the allowlisted state files from the legacy config directory.
//
// Individual failures are logged, not fatal. A missing tasks.sqlite is normal on
// a host that never ran a task, and losing a checkpoint costs a re-read of some
// logs -- neither justifies stranding the agent in the old location.
func copyState(legacyDir, dataDir string) {
	legacyConfigDir := filepath.Join(legacyDir, ".sentinelgo")

	for _, name := range stateFiles {
		src := filepath.Join(legacyConfigDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}

		dst := filepath.Join(dataDir, name)
		if _, err := os.Stat(dst); err == nil {
			log.Printf("Migration: %s already exists at the destination, keeping it", name)
			continue
		}

		if err := copyFile(src, dst); err != nil {
			log.Printf("Migration: could not copy %s: %v", name, err)
			continue
		}

		// SQLite write-ahead log siblings must travel with their database, or a
		// transaction committed to the WAL but not yet checkpointed is lost.
		for _, suffix := range []string{"-wal", "-shm"} {
			sidecarSrc := src + suffix
			if _, err := os.Stat(sidecarSrc); err != nil {
				continue
			}
			if err := copyFile(sidecarSrc, dst+suffix); err != nil {
				log.Printf("Migration: could not copy %s%s: %v", name, suffix, err)
			}
		}
	}

	// The config carries the agent's credentials; harden it explicitly rather
	// than relying on the directory's inheritance alone.
	if err := winsec.SecureSystemPath(filepath.Join(dataDir, "config.json")); err != nil {
		log.Printf("Migration: could not secure the relocated config: %v", err)
	}
}

// repointService rewrites the SCM registration to the new binary and config.
//
// The BinaryPathName is quoted because the new install directory is
// "C:\Program Files\SentinelGo". An unquoted service path containing spaces is
// the textbook unquoted-service-path escalation: the SCM would try C:\Program.exe
// first. mgr.UpdateConfig writes this string verbatim, so the quoting has to be
// correct here.
func repointService(exePath, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", paths.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}

	cfg.BinaryPathName = fmt.Sprintf("%q -config %q", exePath, configPath)

	// Bring a migrated service up to the same configuration a fresh install
	// gets, rather than leaving it a half-upgraded special case.
	cfg.ServiceStartName = "LocalSystem"
	cfg.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED

	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}

	// Recovery actions are what let the agent self-update: it swaps its binary
	// and exits non-zero, relying on the SCM to restart it. A service installed
	// by the old Go -install path never had them configured, so a migrated host
	// would otherwise apply one update and then stay stopped.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		log.Printf("Migration: could not configure service recovery actions: %v. "+
			"Automatic updates will leave the service stopped until this is fixed.", err)
	}

	return nil
}

// writeBreadcrumb leaves a note in the legacy directory for whoever finds it.
func writeBreadcrumb(legacyDir, installDir, dataDir string) {
	note := fmt.Sprintf(
		"SentinelGo has moved.\r\n\r\n"+
			"  Binary: %s\r\n"+
			"  State:  %s\r\n\r\n"+
			"This directory is no longer used and can be deleted once the service is\r\n"+
			"confirmed running from the new location. It was left in place because the\r\n"+
			"binary that performed the migration was executing from here at the time.\r\n",
		filepath.Join(installDir, "sentinelgo.exe"), dataDir)

	path := filepath.Join(legacyDir, "MIGRATED.txt")
	if err := os.WriteFile(path, []byte(note), 0644); err != nil {
		log.Printf("Migration: could not write breadcrumb %s: %v", path, err)
	}
}
