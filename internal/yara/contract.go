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

// Capability is advertised in constants.AgentCapabilities only by the change
// that makes scans work end to end (#416). The backend sends a disabled
// bundle, and no yara-scan task, to agents that don't report it.
const Capability = "yara_scan_v1"

// RPCs and tasks.
const (
	RPCGetRuleset    = "agent_get_yara_ruleset"
	RPCEnqueueEvents = "agent_enqueue_yara_events"

	TaskScan       = "yara-scan"         // native task: start a scan (§4)
	TaskScanCancel = "yara-scan-cancel"  // native task: stop the running scan (§4)
	TaskSync       = "yara-ruleset-sync" // scheduler task: poll the ruleset (#411)
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
	MaxErrorLen     = 200 // skipped-rule reasons and other error strings

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
	TriggerOnWrite   = "on_write" // M2 (#418)
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
