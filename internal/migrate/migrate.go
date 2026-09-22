// Package migrate moves an existing installation to the current on-disk layout.
//
// The Windows agent used to install into C:\SentinelGo. A directory created
// directly under the drive root inherits C:\'s inherit-only
// "Authenticated Users:(OI)(CI)(IO)(M)" ACE, so every standard user could write
// the binary that a LocalSystem service executes (CyberStation PT-2026-001
// finding #1). Fixing the installer protects new installations; this package is
// what moves the ones already out there.
//
// # What this cannot fix
//
// The migration ships inside an update, and that update is downloaded and
// applied by the very binary that may already have been replaced. A host that
// was actually exploited cannot be remediated this way, because the attacker's
// code is what runs the remediation. Such hosts need reimaging. This package is
// for the uncompromised majority, closing the window before anyone uses it.
package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// markerName records a completed migration inside the new data directory.
const markerName = ".migrated.json"

// stateFiles are the files copied from the old layout, by exact name.
//
// An allowlist, never a directory copy: the legacy tree is by definition one a
// standard user could write, so it may contain planted files. Update artifacts
// (*.new, *.backup, *.bat) are conspicuously absent -- copying an executable out
// of an attacker-writable directory into the hardened one would carry the
// problem across rather than leave it behind.
var stateFiles = []string{
	"config.json",
	"audit_checkpoint.json",
	"pending_restart.json",
	"tasks.sqlite",
	"sentinelgo_services.db",
}

// marker is the record written once a migration completes.
type marker struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"at"`
}

// Result describes what Run did.
type Result struct {
	// Migrated is true when files were moved and the service was repointed.
	Migrated bool
	// RestartRequired is true when the caller should exit so the service
	// manager restarts from the new location.
	RestartRequired bool
	// Reason explains why a migration was skipped or abandoned.
	Reason string
}

// writeMarker records a completed migration so subsequent starts skip the work.
func writeMarker(dataDir, from, to, version string) error {
	payload, err := json.MarshalIndent(marker{
		From:      from,
		To:        to,
		Version:   version,
		Timestamp: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, markerName), payload, 0600)
}

// markerExists reports whether a migration has already completed.
func markerExists(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, markerName))
	return err == nil
}

// copyFile copies src to dst, preserving nothing but the bytes.
//
// dst is created with O_EXCL so an existing file at the destination is never
// silently overwritten: during a migration that would mean clobbering state the
// new layout already holds.
func copyFile(src, dst string) error {
	// #nosec G304 - src is drawn from a fixed allowlist under a known root
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return out.Sync()
}

// fileSHA256 returns the hex-encoded SHA-256 of a file.
func fileSHA256(path string) (string, error) {
	// #nosec G304 - path is a controlled install location
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyVerified copies src to dst and confirms the destination reads back with
// the same digest.
//
// Comparing sizes would not be enough for the agent binary: a truncated or
// partially-flushed copy that the service then tries to execute is the failure
// this is here to prevent.
func copyVerified(src, dst string) error {
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}

	srcSum, err := fileSHA256(src)
	if err != nil {
		return fmt.Errorf("hash source %s: %w", src, err)
	}
	dstSum, err := fileSHA256(dst)
	if err != nil {
		return fmt.Errorf("hash destination %s: %w", dst, err)
	}
	if srcSum != dstSum {
		_ = os.Remove(dst)
		return fmt.Errorf("copy of %s did not verify: source %s, destination %s",
			src, srcSum, dstSum)
	}
	return nil
}
