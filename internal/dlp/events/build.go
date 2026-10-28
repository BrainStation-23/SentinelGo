package events

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"sentinelgo/internal/dlp/detect"
)

// Evidence modes (mirrors policy.Evidence*; events can't import policy).
const (
	evidenceNone = "none"
	evidenceFull = "full"
)

// maxExcerptBytes caps the excerpt kept in evidence_mode "full".
const maxExcerptBytes = 512

// Meta is what the channel knows about a flagged copy besides its content.
type Meta struct {
	Channel    string
	User       string
	SessionID  string
	SourceApp  SourceApp
	OccurredAt time.Time
}

// Match is the policy that matched and what it decided.
type Match struct {
	PolicyID      string
	PolicyVersion string
	Action        string // ActionMonitored or ActionBlocked
	Severity      string
	EvidenceMode  string // none | masked | full
}

// Build turns a policy match on content into an event. content is the text
// that was scanned; it never leaves this function except as a hash, a length
// and, in evidence_mode "full" only, a short excerpt around the first finding.
func Build(meta Meta, m Match, res detect.Result, findings []detect.Finding, content string) Event {
	sum := sha256.Sum256([]byte(content))
	ev := Event{
		EventID:       NewID(),
		OccurredAt:    meta.OccurredAt.UTC(),
		Channel:       meta.Channel,
		PolicyID:      m.PolicyID,
		PolicyVersion: m.PolicyVersion,
		Action:        m.Action,
		Severity:      m.Severity,
		User:          meta.User,
		SessionID:     meta.SessionID,
		SourceApp:     meta.SourceApp,
		ContentLength: len(content),
		ContentSHA256: hex.EncodeToString(sum[:]),
		Truncated:     res.Truncated,
		RepeatCount:   1,
	}
	for _, f := range findings {
		fd := Finding{Detector: f.DetectorID, Count: f.Count, Masked: f.Masked, SHA256: f.SHA256}
		if m.EvidenceMode == evidenceNone {
			fd.Masked = ""
		}
		ev.Findings = append(ev.Findings, fd)
	}
	if m.EvidenceMode == evidenceFull && len(findings) > 0 && len(findings[0].Offsets) > 0 {
		ev.Excerpt = excerpt(content, findings[0].Offsets[0])
	}
	return ev
}

// excerpt returns up to maxExcerptBytes of content centred on span, cut on
// rune boundaries.
func excerpt(content string, span [2]int) string {
	start := max(0, span[0]-maxExcerptBytes/4)
	end := min(len(content), start+maxExcerptBytes)
	for start > 0 && !utf8.RuneStart(content[start]) {
		start++
	}
	for end < len(content) && end > start && !utf8.RuneStart(content[end]) {
		end--
	}
	return content[start:end]
}

// DedupeKey groups repeats of the same copy by the same user and session
// under the same policy and action; anything else is a separate event.
func (e Event) DedupeKey() string {
	return strings.Join([]string{e.ContentSHA256, e.PolicyID, e.Action, e.User, e.SessionID}, "\x00")
}

// NewID returns a random (version 4) UUID.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
