package yara

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Event kinds (§3).
const (
	KindMatch       = "match"
	KindScanSummary = "scan_summary"
)

// ErrInvalidEvent is returned by Validate. The server rejects a whole batch
// (22023) for one invalid event, so the agent checks each event before
// queueing it.
var ErrInvalidEvent = errors.New("yara: invalid event")

// Match is one rule matching one file. It carries identifiers, hashes and
// metadata only: never matched bytes, excerpts or file content.
type Match struct {
	ScanID          string   `json:"scan_id"`
	Trigger         string   `json:"trigger"`
	RulesetID       string   `json:"ruleset_id,omitempty"` // the server requires a UUID or no key
	RulesetRevision int      `json:"ruleset_revision"`
	Rule            string   `json:"rule"`
	Namespace       string   `json:"namespace"`
	Tags            []string `json:"tags"`
	// Meta is copied from the rule: string, integer and boolean values
	// only, at most 2 KB.
	Meta map[string]any `json:"meta"`
	// Path is null in hashed path mode; PathHash is then the SHA-256 of the
	// lower-cased path and FileExt (a backend addition) the extension.
	Path       *string   `json:"path"`
	PathHash   *string   `json:"path_hash"`
	FileExt    string    `json:"file_ext,omitempty"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	MTime      time.Time `json:"mtime,omitzero"`
	Owner      string    `json:"owner,omitempty"`
	StringIDs  []string  `json:"string_ids"`
	DetectedAt time.Time `json:"detected_at"`
}

// Event is one entry of agent_enqueue_yara_events: exactly one of Match and
// Summary is set.
type Event struct {
	EventID string
	Match   *Match
	Summary *ScanSummary
}

// Kind returns the event's kind.
func (e Event) Kind() string {
	if e.Match != nil {
		return KindMatch
	}
	return KindScanSummary
}

// MarshalJSON writes the flat §3 shape: event_id, kind and the body's fields.
func (e Event) MarshalJSON() ([]byte, error) {
	switch {
	case e.Match != nil && e.Summary == nil:
		return json.Marshal(struct {
			EventID string `json:"event_id"`
			Kind    string `json:"kind"`
			*Match
		}{e.EventID, KindMatch, e.Match})
	case e.Summary != nil && e.Match == nil:
		return json.Marshal(struct {
			EventID string `json:"event_id"`
			Kind    string `json:"kind"`
			*ScanSummary
		}{e.EventID, KindScanSummary, e.Summary})
	}
	return nil, fmt.Errorf("%w: exactly one of match and summary must be set", ErrInvalidEvent)
}

// UnmarshalJSON reads the flat §3 shape (the on-disk queue stores events
// the way they are sent).
func (e *Event) UnmarshalJSON(data []byte) error {
	var head struct {
		EventID string `json:"event_id"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	*e = Event{EventID: head.EventID}
	switch head.Kind {
	case KindMatch:
		e.Match = &Match{}
		return json.Unmarshal(data, e.Match)
	case KindScanSummary:
		e.Summary = &ScanSummary{}
		return json.Unmarshal(data, e.Summary)
	}
	return fmt.Errorf("%w: unknown kind %q", ErrInvalidEvent, head.Kind)
}

// Validate applies the server's checks (Compliance-OS _yara_valid_match and
// _yara_valid_scan), so a batch the agent sends is never refused for its
// shape.
func (e Event) Validate() error {
	if !IsUUID(e.EventID) {
		return fmt.Errorf("%w: event_id is not a UUID", ErrInvalidEvent)
	}
	switch {
	case e.Match != nil && e.Summary == nil:
		return e.Match.Validate()
	case e.Summary != nil && e.Match == nil:
		return e.Summary.Validate()
	}
	return fmt.Errorf("%w: exactly one of match and summary must be set", ErrInvalidEvent)
}

// Validate checks a match against §3 and the server's limits.
func (m *Match) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidEvent}, a...)...)
	}
	switch {
	case !IsUUID(m.ScanID):
		return bad("scan_id is not a UUID")
	case !ValidTrigger(m.Trigger):
		return bad("unknown trigger %q", m.Trigger)
	case m.RulesetID != "" && !IsUUID(m.RulesetID):
		return bad("ruleset_id is not a UUID")
	case m.RulesetRevision < 0:
		return bad("negative ruleset_revision")
	case m.Rule == "" || len(m.Rule) > MaxRuleLen:
		return bad("rule must be 1-%d characters", MaxRuleLen)
	case len(m.Namespace) > MaxRuleLen:
		return bad("namespace over %d characters", MaxRuleLen)
	case len(m.Tags) > MaxTags:
		return bad("%d tags (max %d)", len(m.Tags), MaxTags)
	case !IsSHA256(m.SHA256):
		return bad("sha256 is not a hex SHA-256")
	case m.Size < 0:
		return bad("negative size")
	case len(m.Owner) > MaxOwnerLen:
		return bad("owner over %d characters", MaxOwnerLen)
	case len(m.FileExt) > MaxFileExtLen:
		return bad("file_ext over %d characters", MaxFileExtLen)
	case len(m.StringIDs) > MaxStringIDs:
		return bad("%d string_ids (max %d)", len(m.StringIDs), MaxStringIDs)
	case m.DetectedAt.IsZero():
		return bad("detected_at missing")
	}
	for _, t := range m.Tags {
		if t == "" || len(t) > MaxTagLen {
			return bad("tags must be 1-%d characters", MaxTagLen)
		}
	}
	for _, s := range m.StringIDs {
		if !IsStringID(s) {
			return bad("string id %q", s)
		}
	}
	if err := validMeta(m.Meta); err != nil {
		return err
	}
	hasPath := m.Path != nil && *m.Path != ""
	if m.Path != nil && len(*m.Path) > MaxPathLen {
		return bad("path over %d characters", MaxPathLen)
	}
	if m.PathHash != nil && !IsSHA256(*m.PathHash) {
		return bad("path_hash is not a hex SHA-256")
	}
	if !hasPath && m.PathHash == nil {
		return bad("needs a path or a path_hash")
	}
	return nil
}

// validMeta accepts scalar values only, at most MaxMetaBytes of JSON.
func validMeta(meta map[string]any) error {
	if meta == nil {
		return nil
	}
	for k, v := range meta {
		switch v.(type) {
		case string, bool, int, int64, float64, json.Number:
		default:
			return fmt.Errorf("%w: meta %q is not a string, number or boolean", ErrInvalidEvent, k)
		}
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("%w: meta: %w", ErrInvalidEvent, err)
	}
	if len(data) > MaxMetaBytes {
		return fmt.Errorf("%w: meta is %d bytes (max %d)", ErrInvalidEvent, len(data), MaxMetaBytes)
	}
	return nil
}

// Validate checks a scan summary (a scan_summary event, or a status's
// last_scan).
func (s *ScanSummary) Validate() error {
	switch {
	case !IsUUID(s.ScanID):
		return fmt.Errorf("%w: scan_id is not a UUID", ErrInvalidEvent)
	case !ValidTrigger(s.Trigger):
		return fmt.Errorf("%w: unknown trigger %q", ErrInvalidEvent, s.Trigger)
	case !ValidScanState(s.State):
		return fmt.Errorf("%w: unknown scan state %q", ErrInvalidEvent, s.State)
	case s.Preset != "" && !ValidPreset(s.Preset):
		return fmt.Errorf("%w: unknown preset %q", ErrInvalidEvent, s.Preset)
	case s.FilesScanned < 0 || s.FilesSkipped < 0 || s.Errors < 0 || s.Matches < 0:
		return fmt.Errorf("%w: negative count", ErrInvalidEvent)
	}
	return nil
}
