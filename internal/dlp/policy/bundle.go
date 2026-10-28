// Package policy holds the DLP policy bundle the backend serves to each device
// (agent_get_dlp_policy, contract in sentinel-ops docs/dlp.md) and its compiled,
// ready-to-enforce form.
package policy

// SchemaVersion is the bundle schema this agent understands.
const SchemaVersion = 1

// Action modes for a policy.
const (
	ActionMonitor = "monitor" // record evidence only
	ActionBlock   = "block"   // replace the content and record evidence
)

// Evidence modes for the whole bundle.
const (
	EvidenceNone   = "none"
	EvidenceMasked = "masked"
	EvidenceFull   = "full"
)

// Bundle is the device's DLP policy bundle (schema_version 1).
type Bundle struct {
	SchemaVersion       int      `json:"schema_version"`
	Version             string   `json:"version"`
	Enabled             bool     `json:"enabled"`
	PollIntervalSeconds int      `json:"poll_interval_seconds"`
	EvidenceMode        string   `json:"evidence_mode"`
	Modules             Modules  `json:"modules"`
	Policies            []Policy `json:"policies"`
}

// Modules holds the per-channel settings. Only the clipboard exists so far.
type Modules struct {
	Clipboard ClipboardModule `json:"clipboard"`
}

// ClipboardModule configures the clipboard channel.
type ClipboardModule struct {
	Enabled         bool   `json:"enabled"`
	MaxScanBytes    int    `json:"max_scan_bytes"`
	IgnoreConcealed bool   `json:"ignore_concealed"`
	BlockMessage    string `json:"block_message"`
	NotifyMessage   string `json:"notify_message"`
}

// Policy is one admin-defined policy.
type Policy struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Severity   string     `json:"severity"`
	Channels   []string   `json:"channels"`
	Action     string     `json:"action"`
	Match      string     `json:"match"`
	Detectors  []Detector `json:"detectors"`
	Exceptions Exceptions `json:"exceptions"`
}

// Detector is one rule of a policy. Pattern applies to custom.regex, Keywords
// and CaseSensitive to custom.keywords.
type Detector struct {
	ID            string   `json:"id"`
	RuleID        string   `json:"rule_id"`
	MinCount      int      `json:"min_count"`
	Pattern       string   `json:"pattern,omitempty"`
	Keywords      []string `json:"keywords,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

// Exceptions lists what a policy never applies to.
type Exceptions struct {
	SourceApps []string `json:"source_apps,omitempty"`
}
