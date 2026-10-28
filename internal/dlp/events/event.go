// Package events defines the DLP evidence event a channel records when content
// matches a policy (contract: sentinel-ops#468). Events never carry the raw
// content: only masked matches, hashes and lengths, plus an excerpt when the
// bundle's evidence_mode is "full". Masking, hashing and dedupe are added with
// the evidence queue (#261).
package events

import "time"

// Actions recorded on an event.
const (
	ActionMonitored = "monitored"
	ActionBlocked   = "blocked"
)

// Event is one flagged copy (or other channel action).
type Event struct {
	EventID       string    `json:"event_id"` // agent-generated UUID, the idempotency key
	OccurredAt    time.Time `json:"occurred_at"`
	Channel       string    `json:"channel"`
	PolicyID      string    `json:"policy_id"`
	PolicyVersion string    `json:"policy_version"`
	Action        string    `json:"action"`
	Severity      string    `json:"severity"`
	User          string    `json:"user"`
	SessionID     string    `json:"session_id"`
	SourceApp     SourceApp `json:"source_app"`
	Findings      []Finding `json:"findings"`
	ContentLength int       `json:"content_length"`
	ContentSHA256 string    `json:"content_sha256"`
	Truncated     bool      `json:"truncated"`
	Excerpt       string    `json:"excerpt,omitempty"`
	RepeatCount   int       `json:"repeat_count"`
}

// SourceApp identifies the application the content came from, when known.
type SourceApp struct {
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	BundleID string `json:"bundle_id,omitempty"`
}

// Finding is what one detector matched, without the matched text.
type Finding struct {
	Detector string `json:"detector"`
	Count    int    `json:"count"`
	Masked   string `json:"masked,omitempty"`
	SHA256   string `json:"sha256"`
}
