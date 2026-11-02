// Package events defines the DLP evidence event a channel records when content
// matches a policy (contract: sentinel-ops#468). Events never carry the raw
// content: only masked matches, hashes and lengths, plus an excerpt when the
// bundle's evidence_mode is "full". Masking, hashing and dedupe are added with
// the evidence queue (#261).
package events

import (
	"strings"
	"time"
)

// Actions recorded on an event.
const (
	ActionMonitored = "monitored"
	ActionWarned    = "warned"
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

	// File channels only (contract #326); nil for the clipboard.
	File        *File        `json:"file,omitempty"`
	Destination *Destination `json:"destination,omitempty"`
	Process     *Process     `json:"process,omitempty"`
	Scan        *Scan        `json:"scan,omitempty"`
}

// File is the file a file-channel event is about. Name follows the bundle's
// evidence mode (see FileName); content and extracted text are never sent.
type File struct {
	Name         *string `json:"name"` // null in evidence_mode "none"
	Ext          string  `json:"ext,omitempty"`
	DetectedType string  `json:"detected_type,omitempty"` // e.g. "ooxml.xlsx"
	Size         int64   `json:"size"`
	SHA256       string  `json:"sha256,omitempty"`
}

// Destination is where the file was going.
type Destination struct {
	Type        string `json:"type"` // removable, network_share, upload, cloud_sync
	VolumeLabel string `json:"volume_label,omitempty"`
	USB         *USB   `json:"usb,omitempty"`
	ShareHost   string `json:"share_host,omitempty"`
	Host        string `json:"host,omitempty"` // uploads: the host only, never the URL
}

// USB identifies a removable device.
type USB struct {
	VendorID  string `json:"vendor_id,omitempty"`
	ProductID string `json:"product_id,omitempty"`
	Serial    string `json:"serial,omitempty"`
}

// Process is the program that moved the file.
type Process struct {
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// Scan describes how the verdict was reached.
type Scan struct {
	Status        string `json:"status"`         // scanned, truncated, unscannable:<reason>, timeout
	VerdictSource string `json:"verdict_source"` // scan, cache, correlation
	DurationMs    int64  `json:"duration_ms"`
}

// FileName returns what an event may say about a file at path (#341): nothing
// in evidence mode "none", the full path in "full", and otherwise ("masked")
// only the base name, so the user-profile part of the path never leaves the
// device.
func FileName(evidenceMode, path string) *string {
	switch evidenceMode {
	case "none":
		return nil
	case "full":
		return &path
	}
	name := path
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return &name
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
