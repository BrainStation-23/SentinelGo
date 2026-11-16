package yara

import (
	"encoding/json"
	"time"
)

// Status states (§2). tcc_denied is a backend addition: macOS without Full
// Disk Access (#413).
const (
	StateOK                = "ok"
	StateDisabled          = "disabled"
	StateCompileFailed     = "compile_failed"
	StateDownloadFailed    = "download_failed"
	StateTooLarge          = "too_large"
	StateUnsupportedSchema = "unsupported_schema"
	StateWorkerUnavailable = "worker_unavailable"
	StateTCCDenied         = "tcc_denied"
)

// Status is what the device applied, sent as p_status on the ruleset poll.
// The server rejects it over 64 KB, or malformed, with 22023; Encode keeps
// it inside both.
type Status struct {
	AppliedVersion string          `json:"applied_version"`
	AgentVersion   string          `json:"agent_version"`
	EngineVersion  string          `json:"engine_version"`
	State          string          `json:"state"`
	Rulesets       []RulesetStatus `json:"rulesets"`
	LastScan       *ScanSummary    `json:"last_scan"`
}

// RulesetStatus is how one ruleset compiled.
type RulesetStatus struct {
	ID            string        `json:"id"`
	Revision      int           `json:"revision"`
	CompiledRules int           `json:"compiled_rules"`
	SkippedRules  []SkippedRule `json:"skipped_rules"`
}

// SkippedRule is a rule that didn't compile, e.g. reason
// "unsupported_module:pe". The console shows these so admins know what
// isn't covered (#411).
type SkippedRule struct {
	Rule   string `json:"rule"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// ScanSummary describes one scan: the status's last_scan, and the body of a
// scan_summary event.
type ScanSummary struct {
	ScanID  string `json:"scan_id"`
	Trigger string `json:"trigger"`
	// Preset is a backend addition: alerts auto-resolve only after a full
	// scan, so the agent always sends it.
	Preset       string    `json:"preset,omitempty"`
	StartedAt    time.Time `json:"started_at,omitzero"`
	FinishedAt   time.Time `json:"finished_at,omitzero"`
	State        string    `json:"state"`
	FilesScanned int64     `json:"files_scanned"`
	FilesSkipped int64     `json:"files_skipped"`
	Errors       int64     `json:"errors"`
	Matches      int64     `json:"matches"`
	// Truncated: the scan hit the per-scan match event cap (#415), so not
	// every match was sent.
	Truncated bool `json:"truncated,omitempty"`
	// RuleCounts lists every rule the scan found and in how many files,
	// whether or not the match was sent (scheduled scans don't re-send
	// matches already reported). The server clears a match alert only when
	// a full scan's complete list leaves the rule out (contract v1.2,
	// SentinelGo#496). nil (JSON null) means not counted; an empty list
	// means nothing was found.
	RuleCounts []RuleCount `json:"rule_counts"`
	// RuleCountsTruncated: RuleCounts is incomplete, so it must not clear
	// anything: the list was cut at MaxRuleCounts, or a file that matched
	// in an earlier scan couldn't be scanned this time.
	RuleCountsTruncated bool `json:"rule_counts_truncated,omitempty"`

	// Contract v1.2 report (#497), all optional. SkippedByReason sums to
	// FilesSkipped and ErrorsByReason to Errors.
	SkippedByReason map[string]int64 `json:"skipped_by_reason,omitempty"`
	ErrorsByReason  map[string]int64 `json:"errors_by_reason,omitempty"`
	// EndReason says why the scan stopped early; empty when it completed.
	EndReason        string `json:"end_reason,omitempty"`
	BytesScanned     int64  `json:"bytes_scanned,omitempty"`
	ThrottledSeconds int64  `json:"throttled_seconds,omitempty"`
	Scope            *Scope `json:"scope,omitempty"`
	// ProblemFiles is a sample of the files the scan couldn't read or
	// skipped for a reason an admin can act on (errors first).
	ProblemFiles []ProblemFile `json:"problem_files,omitempty"`
}

// Scope is what a scan covered: folders, exclusions, limits and rulesets.
// In hashed path mode the folders are path hashes, like match paths.
type Scope struct {
	Roots      []string       `json:"roots"`
	Exclusions []string       `json:"exclusions"`
	Limits     ScopeLimits    `json:"limits"`
	Rulesets   []ScopeRuleset `json:"rulesets"`
}

// ScopeLimits are the bundle limits the scan ran under.
type ScopeLimits struct {
	MaxFileBytes     int64 `json:"max_file_bytes"`
	PerFileTimeoutMS int   `json:"per_file_timeout_ms"`
	MaxScanMinutes   int   `json:"max_scan_minutes"`
	MaxFilesPerScan  int   `json:"max_files_per_scan"`
}

// ScopeRuleset is one ruleset the scan used.
type ScopeRuleset struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}

// ProblemFile is one file (or folder) a scan couldn't scan. It follows the
// path evidence rules of a match: in hashed mode PathHash and FileExt only.
// Detail is the OS error text, never file content.
type ProblemFile struct {
	Path     *string `json:"path,omitempty"`
	PathHash *string `json:"path_hash,omitempty"`
	FileExt  string  `json:"file_ext,omitempty"`
	Reason   string  `json:"reason"`
	Detail   string  `json:"detail,omitempty"`
	Size     int64   `json:"size,omitempty"`
}

// RuleCount is one rule a scan found and the number of files it matched.
type RuleCount struct {
	RulesetID string `json:"ruleset_id,omitempty"`
	Rule      string `json:"rule"`
	Files     int64  `json:"files"`
}

// statusBudget leaves room under the server's 64 KB for its own JSON
// rendering, which can be a little larger than ours.
const statusBudget = MaxStatusBytes - 4<<10

// Encode returns the status as JSON within the contract's caps: at most 50
// rulesets, 100 skipped rules each, strings cut to their limits. If that is
// still over the size budget, skipped rules are dropped, from the longest
// list first, until it fits. The input isn't modified.
func (s Status) Encode() ([]byte, error) {
	c := s.capped()
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	for len(data) > statusBudget {
		if !c.dropSkipped() {
			c.Rulesets = c.Rulesets[:len(c.Rulesets)/2]
		}
		if data, err = json.Marshal(c); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (s Status) capped() Status {
	s.AppliedVersion = Truncate(s.AppliedVersion, MaxVersionLen)
	s.AgentVersion = Truncate(s.AgentVersion, MaxAgentVerLen)
	s.EngineVersion = Truncate(s.EngineVersion, MaxAgentVerLen)
	rs := s.Rulesets[:min(len(s.Rulesets), MaxRulesets)]
	s.Rulesets = make([]RulesetStatus, len(rs))
	for i, r := range rs {
		sk := r.SkippedRules[:min(len(r.SkippedRules), MaxSkippedRules)]
		r.SkippedRules = make([]SkippedRule, len(sk))
		for j, k := range sk {
			k.Rule = Truncate(k.Rule, MaxRuleLen)
			k.Reason = Truncate(k.Reason, MaxErrorLen)
			r.SkippedRules[j] = k
		}
		s.Rulesets[i] = r
	}
	s.LastScan = s.LastScan.Brief()
	return s
}

// Brief is the summary without its lists, for the status and the
// inventory: their counts, not up to 500 rules (they would not fit the
// 64 KB status), and no paths (scope and problem files go with the
// scan_summary event only).
func (s *ScanSummary) Brief() *ScanSummary {
	if s == nil {
		return nil
	}
	b := *s
	b.RuleCounts, b.RuleCountsTruncated = nil, false
	b.Scope, b.ProblemFiles = nil, nil
	return &b
}

// dropSkipped halves the longest skipped-rule list. It reports false when
// there is nothing left to drop.
func (s *Status) dropSkipped() bool {
	longest := -1
	for i, r := range s.Rulesets {
		if len(r.SkippedRules) > 0 && (longest < 0 || len(r.SkippedRules) > len(s.Rulesets[longest].SkippedRules)) {
			longest = i
		}
	}
	if longest < 0 {
		return false
	}
	sk := s.Rulesets[longest].SkippedRules
	s.Rulesets[longest].SkippedRules = sk[:len(sk)/2]
	return true
}

// Summary is the compact threat hunting health in the inventory payload
// (#416), so the console can show "scanning works on this device" without
// parsing the status. It carries counts and states only, never rule text.
type Summary struct {
	State string `json:"state"`
	// LocalEnabled is config.json's yara_enabled.
	LocalEnabled   bool   `json:"local_enabled"`
	AppliedVersion string `json:"applied_version,omitempty"`
	Rulesets       int    `json:"rulesets"`
	CompiledRules  int    `json:"compiled_rules"`
	SkippedRules   int    `json:"skipped_rules"`
	// WorkersHealthy is false when the scan workers were disabled after a
	// crash loop.
	WorkersHealthy bool `json:"workers_healthy"`
	// Scanning is the running scan's id.
	Scanning     string       `json:"scanning,omitempty"`
	LastScan     *ScanSummary `json:"last_scan,omitempty"`
	QueuedEvents int          `json:"queued_events"`
}

// SummaryOf condenses a status.
func SummaryOf(st Status) Summary {
	s := Summary{State: st.State, AppliedVersion: st.AppliedVersion, Rulesets: len(st.Rulesets), LastScan: st.LastScan.Brief()}
	for _, r := range st.Rulesets {
		s.CompiledRules += r.CompiledRules
		s.SkippedRules += len(r.SkippedRules)
	}
	return s
}
