// Package paths is the single source of truth for where the agent keeps its
// binary, its configuration and its mutable state.
//
// These locations used to be spelled out independently in config, lockfile,
// procinfo, osinfo/system and the task manager. Beyond the obvious drift risk,
// one of those spellings was a security defect: on Windows the agent installed
// into C:\SentinelGo, and a directory created directly under C:\ inherits the
// drive root's "NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)" ACE. That is
// an inherit-only Modify grant which propagates to every child, so any standard
// user could replace sentinelgo.exe and have it executed by a LocalSystem
// service (CyberStation PT-2026-001 finding #1).
//
// The layout below fixes that by construction:
//
//	Windows   binary  %ProgramFiles%\SentinelGo\sentinelgo.exe
//	          staging %ProgramFiles%\SentinelGo\.staging
//	          state   %ProgramData%\SentinelGo
//	Unix      binary  /opt/sentinelgo/sentinelgo
//	          staging /opt/sentinelgo/.staging
//	          state   /opt/sentinelgo/.sentinelgo
//
// %ProgramFiles% denies writes to non-administrators by default. %ProgramData%
// does NOT: its default DACL grants BUILTIN\Users read and CREATOR OWNER full
// control over children. Since the state directory holds cleartext credentials,
// callers must still apply an explicit protected DACL there via internal/winsec.
// Choosing the right directory removes the write primitive; it does not remove
// the read one.
//
// Staging deliberately sits beside the binary so that swapping in an update is
// an intra-volume rename rather than a cross-volume copy.
package paths

import (
	"path/filepath"
	"strings"
)

// ServiceName is the name the agent is registered under with the OS service
// manager (the Windows SCM service name, and the systemd/launchd unit stem).
//
// It lives here, alongside the paths, because this package is the dependency-free
// leaf that every layer can import: the updater, the migration logic and the
// service lifecycle code each need it, and three private copies of the same
// string is precisely the drift this package exists to prevent.
const ServiceName = "SentinelGo"

// Well-known file names within DataDir. Centralised so a rename cannot leave one
// caller writing to the old name.
const (
	configFileName     = "config.json"
	taskDBFileName     = "tasks.sqlite"
	servicesDBFileName = "sentinelgo_services.db"
	checkpointFileName = "audit_checkpoint.json"
)

// InstallDir returns the directory holding the agent binary.
func InstallDir() string { return installDir() }

// DataDir returns the directory holding configuration and mutable state.
func DataDir() string { return dataDir() }

// StagingDir returns the directory used for update artifacts (the downloaded
// binary, its backup, and any restart helper). It lives beside the binary so the
// final swap is a rename on the same volume.
func StagingDir() string { return filepath.Join(installDir(), ".staging") }

// ConfigPath returns the full path to config.json.
func ConfigPath() string { return filepath.Join(dataDir(), configFileName) }

// TaskDBPath returns the task queue database path.
func TaskDBPath() string { return filepath.Join(dataDir(), taskDBFileName) }

// ServicesDBPath returns the collected-services database path.
func ServicesDBPath() string { return filepath.Join(dataDir(), servicesDBFileName) }

// CheckpointPath returns the audit-log checkpoint path.
func CheckpointPath() string { return filepath.Join(dataDir(), checkpointFileName) }

// LockPath returns the path of the named process lock file.
//
// The lock lives in DataDir with everything else. It previously sat under
// %USERPROFILE%, which for a LocalSystem service resolves to
// C:\Windows\System32\config\systemprofile — making it the only piece of agent
// state outside the directory the hardening logic knows about.
func LockPath(name string) string { return filepath.Join(dataDir(), name+".lock") }

// LegacyInstallDir returns the pre-relocation install directory, or "" on
// platforms that were never relocated. Migration code is the only caller.
func LegacyInstallDir() string { return legacyInstallDir() }

// LegacyConfigPath returns the pre-relocation config path, or "" where there is
// none. Used so a new binary started before migration finishes can still find
// the agent's identity.
func LegacyConfigPath() string {
	legacy := legacyInstallDir()
	if legacy == "" {
		return ""
	}
	return filepath.Join(legacy, ".sentinelgo", configFileName)
}

// IsManagedPath reports whether p lies inside a directory this package owns.
//
// It gates the permission hardening applied on config load. That gate is not
// cosmetic: Load is also called by tests with temporary directories and by CLI
// subcommands with an arbitrary -config value, and the hardened DACL grants
// access to SYSTEM and Administrators only. Applying it to a developer's temp
// directory would lock the calling process out of its own files.
func IsManagedPath(p string) bool {
	if p == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}

	roots := []string{installDir(), dataDir()}
	if legacy := legacyInstallDir(); legacy != "" {
		roots = append(roots, legacy)
	}

	for _, root := range roots {
		if root != "" && isWithin(root, abs) {
			return true
		}
	}
	return false
}

// isWithin reports whether path is root or lies beneath it. Comparison is
// case-insensitive on Windows, where paths are not case-sensitive.
func isWithin(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	// filepath.Rel yields a ".." prefix exactly when path escapes root.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}
