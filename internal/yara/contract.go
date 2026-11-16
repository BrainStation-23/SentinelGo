// Package yara holds the threat hunting (YARA) contract shared with the
// backend: the ruleset bundle served by agent_get_yara_ruleset, the status
// the agent reports on the same call, the match and scan-summary events sent
// to agent_enqueue_yara_events, and the yara-scan native task (contract v1,
// SentinelGo#409; how the backend serves it: Compliance-OS docs/yara.md).
//
// This is threat hunting, not an antivirus: the agent finds files that rules
// describe and reports identifiers, hashes and paths. Nothing in this package
// carries matched bytes or file content, and nothing may be added that does.
package yara

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

// SchemaVersion is the bundle schema this agent understands.
const SchemaVersion = 1

// Capability is advertised in constants.AgentCapabilities (#416). The
// backend sends a disabled bundle, and no yara-scan task, to agents that
// don't report it.
const Capability = "yara_scan_v1"

// CapabilityOnWrite is advertised next to Capability by agents that scan
// files as they are written (contract v1.1, #418). The backend sends an
// enabled on_write block only to agents that report it.
const CapabilityOnWrite = "yara_on_write_v1"

// CapabilityScanReport is advertised by agents whose scan_summary carries
// the contract v1.2 report fields: skip and error reasons, end reason,
// scope, problem files (#497). They are optional, so v1 servers ignore them.
const CapabilityScanReport = "yara_scan_report_v1"

// RPCs and tasks.
const (
	RPCGetRuleset    = "agent_get_yara_ruleset"
	RPCEnqueueEvents = "agent_enqueue_yara_events"

	TaskScan       = "yara-scan"           // native task: start a scan (§4)
	TaskScanCancel = "yara-scan-cancel"    // native task: stop the running scan (§4)
	TaskSync       = "yara-ruleset-sync"   // scheduler task: poll the ruleset (#411)
	TaskScheduler  = "yara-scan-scheduler" // scheduler task: start due scheduled scans (#414)
	TaskEventSync  = "yara-event-sync"     // scheduler task: upload queued events (#415)
)

// SQLStateInvalid is the PostgREST code both RPCs use for a payload they
// refuse (a malformed status, an invalid event batch). The agent doesn't
// resend the same payload.
const SQLStateInvalid = "22023"

// Contract caps (§2, §3). The agent refuses or trims anything larger, so the
// server never has to reject it.
const (
	MaxBundleBytes     = 256 << 10 // bundle JSON
	MaxRulesetBytes    = 5 << 20   // one rule source in Storage
	MaxBundleRuleBytes = 20 << 20  // all rule sources of a bundle
	MaxRulesets        = 50

	MaxStatusBytes  = 64 << 10
	MaxSkippedRules = 100 // per ruleset in a status
	MaxRuleCounts   = 500 // scan_summary rule_counts (the server takes up to 1,000)
	MaxErrorLen     = 200 // skipped-rule reasons and other error strings

	// scan_summary report fields (contract v1.2, #497), as the server's
	// _yara_valid_scan_report checks them.
	MaxSummaryBytes    = 32 << 10 // problem_files go first, then rule_counts
	MaxReasons         = 32       // keys of skipped_by_reason / errors_by_reason
	MaxProblemFiles    = 200
	MaxProblemDetail   = 200
	MaxScopeRoots      = 100
	MaxScopeExclusions = 200
	MaxScopeBytes      = 64 << 10

	MaxEventsPerCall = 500
	MaxMetaBytes     = 2 << 10
	MaxStringIDs     = 50
	MaxTags          = 20
	MaxTagLen        = 64
	MaxRuleLen       = 256 // rule and namespace names
	MaxPathLen       = 4096
	MaxOwnerLen      = 256
	MaxFileExtLen    = 32
	MaxVersionLen    = 200 // bundle version (status applied_version)
	MaxAgentVerLen   = 64  // agent_version, engine_version
)

// Presets (§2 schedules, §4 task).
const (
	PresetQuick  = "quick"
	PresetFull   = "full"
	PresetCustom = "custom"
)

// ValidPreset reports whether p is a preset the contract defines.
func ValidPreset(p string) bool {
	return p == PresetQuick || p == PresetFull || p == PresetCustom
}

// Scan triggers.
const (
	TriggerScheduled = "scheduled"
	TriggerOnDemand  = "on_demand"
	TriggerOnWrite   = "on_write" // contract v1.1 (#418)
)

// ValidTrigger reports whether t is a trigger the contract defines.
func ValidTrigger(t string) bool {
	return t == TriggerScheduled || t == TriggerOnDemand || t == TriggerOnWrite
}

// Scan end states (status last_scan, scan_summary).
const (
	ScanCompleted = "completed"
	ScanPartial   = "partial" // stopped by max_scan_minutes / max_files_per_scan; resumes next window
	ScanCancelled = "cancelled"
	ScanFailed    = "failed"
)

// ValidScanState reports whether s is a scan end state the contract defines.
func ValidScanState(s string) bool {
	return s == ScanCompleted || s == ScanPartial || s == ScanCancelled || s == ScanFailed
}

// Why a scan ended early (scan_summary end_reason, contract v1.2). A
// completed scan has none.
const (
	EndTimeLimit     = "time_limit"
	EndFileLimit     = "file_limit"
	EndCancelled     = "cancelled"
	EndDisabled      = "disabled"
	EndWorkerFailure = "worker_failure"
	EndNoRules       = "no_rules"
	EndShutdown      = "shutdown"
	EndError         = "error"
)

// ValidEndReason reports whether r is an end reason the contract defines.
func ValidEndReason(r string) bool {
	switch r {
	case EndTimeLimit, EndFileLimit, EndCancelled, EndDisabled, EndWorkerFailure, EndNoRules, EndShutdown, EndError:
		return true
	}
	return false
}

// Per-file reasons the scan adds to the walk's skip reasons
// (skipped_by_reason), and error reasons (errors_by_reason).
const (
	SkipTimeout = "timeout" // the per-file timeout
	SkipChanged = "changed" // changed or gone since it was listed

	ErrAccessDenied = "access_denied"
	ErrLocked       = "locked" // sharing violation, in use
	ErrRead         = "read_error"
	ErrList         = "list_error" // a folder couldn't be listed, or a file stat'ed
	ErrWorkerFailed = "worker_failed"
	ErrQueue        = "queue_error" // match events couldn't be queued on disk
)

var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// IsReason reports whether s is a reason name the server accepts.
func IsReason(s string) bool { return reasonRE.MatchString(s) }

// Path evidence modes (bundle evidence.path_mode).
const (
	PathModeFull   = "full"
	PathModeHashed = "hashed"
)

var (
	uuidRE     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	stringIDRE = regexp.MustCompile(`^\$[A-Za-z0-9_]{0,127}$`)
)

// IsUUID reports whether s is a UUID in the 8-4-4-4-12 hex form the backend
// checks.
func IsUUID(s string) bool { return uuidRE.MatchString(s) }

// IsSHA256 reports whether s is a hex SHA-256.
func IsSHA256(s string) bool { return sha256RE.MatchString(s) }

// IsStringID reports whether s is a YARA string identifier ($name).
func IsStringID(s string) bool { return stringIDRE.MatchString(s) }

// NewID returns a random (version 4) UUID, for event and scan ids.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
