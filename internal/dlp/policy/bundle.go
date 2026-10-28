// Package policy holds the DLP policy bundle the backend serves to each device
// (agent_get_dlp_policy, contract in sentinel-ops docs/dlp.md) and its compiled,
// ready-to-enforce form.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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

// Limits and defaults applied when decoding a bundle.
const (
	// MaxBundleBytes bounds a bundle from the server or the cache.
	MaxBundleBytes = 8 << 20

	DefaultPollInterval = 300 * time.Second
	MinPollInterval     = 60 * time.Second
	MaxPollInterval     = time.Hour

	DefaultMaxScanBytes = 1 << 20
)

// ErrUnsupportedSchema is returned for a bundle whose schema_version this
// agent doesn't understand. The caller keeps its last-known bundle.
var ErrUnsupportedSchema = errors.New("unsupported DLP bundle schema_version")

// Decode parses and normalizes a bundle.
func Decode(data []byte) (*Bundle, error) {
	if len(data) > MaxBundleBytes {
		return nil, fmt.Errorf("DLP bundle is %d bytes, over the %d-byte limit", len(data), MaxBundleBytes)
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decode DLP bundle: %w", err)
	}
	if b.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %d (this agent understands %d)", ErrUnsupportedSchema, b.SchemaVersion, SchemaVersion)
	}
	if b.Version == "" {
		return nil, errors.New("DLP bundle has no version")
	}
	b.normalize()
	return &b, nil
}

// normalize fills defaults the server may leave out.
func (b *Bundle) normalize() {
	if b.EvidenceMode != EvidenceNone && b.EvidenceMode != EvidenceFull {
		b.EvidenceMode = EvidenceMasked
	}
	if b.Modules.Clipboard.MaxScanBytes <= 0 {
		b.Modules.Clipboard.MaxScanBytes = DefaultMaxScanBytes
	}
}

// PollInterval is how often to poll for a new bundle: the bundle's
// poll_interval_seconds clamped to 1 minute–1 hour, or 5 minutes without a
// bundle.
func (b *Bundle) PollInterval() time.Duration {
	if b == nil || b.PollIntervalSeconds <= 0 {
		return DefaultPollInterval
	}
	d := time.Duration(b.PollIntervalSeconds) * time.Second
	return min(max(d, MinPollInterval), MaxPollInterval)
}

// AnyChannelEnabled reports whether at least one channel module is on.
func (b *Bundle) AnyChannelEnabled() bool {
	return b.Modules.Clipboard.Enabled
}
