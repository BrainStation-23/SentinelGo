// Package selfdefense verifies, at every start, that the agent is running from
// a location a standard user cannot tamper with.
//
// The agent runs as LocalSystem (root on Unix). If its binary, its install
// directory or its configuration can be written by an unprivileged account, that
// account has a direct path to full system privileges: replace the binary and
// wait for the service to restart, or repoint supabase_url and take over the
// control plane that hands the agent scripts to execute. That is CyberStation
// PT-2026-001 finding #1, and the relocation to %ProgramFiles% plus the
// installer's ACL work is what fixes it.
//
// This package exists because a fix applied at install time is only ever a
// snapshot. Permissions drift: an operator "fixes" an access problem with
// icacls, a backup tool restores an inherited ACL, a half-finished migration
// leaves the old tree behind. Checking on every start turns a one-time
// correction into a standing invariant, and makes a regression visible instead
// of silent.
//
// # What this cannot do
//
// An ACL audit cannot detect a binary that has ALREADY been replaced. By the
// time this code runs it is the attacker's code running it. Detecting that needs
// a root of trust outside the binary -- Authenticode with WinVerifyTrust, or
// comparing the running image's hash against the backend's published value for
// this version. Neither is in place yet, so this check is a guard against
// becoming exploitable, not a guarantee of not already being so.
package selfdefense

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync/atomic"

	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/paths"
	"sentinelgo/internal/winsec"
)

// degraded records that a start-time integrity check failed. It is process-wide
// and one-way: nothing clears it short of a restart, so a subsystem cannot be
// re-enabled by a later, more optimistic check.
var (
	degraded   atomic.Bool
	reasonText atomic.Value // string
)

// Degraded reports whether this process failed its start-time integrity check.
//
// Callers use it to suppress the two subsystems that fetch and execute further
// code as LocalSystem: automatic updates and remote task execution. In a
// suspected-compromise state the agent's job is to keep reporting, not to keep
// acting. Everything else -- heartbeat, inventory, services and audit-log
// collection -- carries on, because losing visibility is the worst outcome
// available and is exactly what an attacker would want.
func Degraded() bool { return degraded.Load() }

// Reason returns a human-readable explanation of the degraded state, or "".
func Reason() string {
	if r, ok := reasonText.Load().(string); ok {
		return r
	}
	return ""
}

// Result is the outcome of a Check.
type Result struct {
	// Secure is true when every audited path passed.
	Secure bool
	// Reason describes the failures, empty when Secure.
	Reason string
	// Fatal is true when the agent should refuse to start.
	Fatal bool
}

// Check audits the agent's install and configuration locations, attempts to
// repair anything insecure, and records the outcome.
//
// The policy is verify, re-harden, report, then continue degraded -- not refuse
// to start. Refusing would convert a permissions misconfiguration into a
// fleet-wide outage of the security agent, and would hand anyone who *can* write
// the directory a trivial and permanent denial of service: one bad ACE and the
// agent never starts again.
//
// The single exception is a path we could not secure while running as the most
// privileged account on the machine. There we hold every right that could be
// required, so the failure means something is actively resisting, and continuing
// to run as LocalSystem out of a directory we cannot control is worse than
// stopping.
func Check(configPath string) Result {
	targets := auditTargets(configPath)

	insecure := auditAll(targets)
	if len(insecure) == 0 {
		return Result{Secure: true}
	}

	reason := strings.Join(insecure, "; ")
	log.Printf("CRITICAL: agent integrity check failed: %s", reason)
	emergencylog.Record("integrity", "start-time integrity check failed: %s", reason)

	// Try to repair, then re-audit rather than trusting the repair succeeded.
	for _, target := range targets {
		if err := winsec.SecureSystemPath(target); err != nil {
			log.Printf("Self-defense: could not secure %s: %v", target, err)
		}
	}

	stillInsecure := auditAll(targets)
	if len(stillInsecure) == 0 {
		log.Printf("Self-defense: insecure permissions were repaired: %s", reason)
		emergencylog.Record("integrity", "insecure permissions repaired: %s", reason)
		return Result{Secure: true}
	}

	finalReason := strings.Join(stillInsecure, "; ")
	degraded.Store(true)
	reasonText.Store(finalReason)

	// As LocalSystem/root we had every privilege the repair could need.
	fatal := winsec.RunningAsSystem()
	if fatal {
		log.Printf("CRITICAL: running with full privileges yet unable to secure %s. "+
			"Refusing to start: continuing would run a privileged service from a "+
			"location that something else controls.", finalReason)
		emergencylog.Record("integrity",
			"refusing to start: could not secure paths despite full privileges: %s", finalReason)
	} else {
		log.Printf("WARNING: continuing in degraded mode. Automatic updates and remote "+
			"task execution are disabled because the agent cannot verify it is running "+
			"from a protected location: %s", finalReason)
		emergencylog.Record("integrity", "degraded mode: updates and task execution disabled: %s",
			finalReason)
	}

	return Result{Secure: false, Reason: finalReason, Fatal: fatal}
}

// auditTargets lists the paths whose permissions matter, skipping any that do
// not exist yet (the staging directory is created on first update).
func auditTargets(configPath string) []string {
	targets := []string{
		paths.InstallDir(),
		paths.DataDir(),
	}
	if configPath != "" {
		targets = append(targets, filepath.Dir(configPath), configPath)
	}
	if staging := paths.StagingDir(); staging != "" {
		targets = append(targets, staging)
	}
	return dedupeExisting(targets)
}

// auditAll returns a description for each target that failed its audit.
func auditAll(targets []string) []string {
	var failures []string
	for _, target := range targets {
		audit, err := winsec.AuditPath(target)
		if err != nil {
			// A path that vanished between listing and auditing is not a
			// finding; anything else is worth surfacing.
			log.Printf("Self-defense: could not audit %s: %v", target, err)
			continue
		}
		if !audit.Secure() {
			failures = append(failures, fmt.Sprintf("%s (%s)", target, audit.Reason()))
		}
	}
	return failures
}
