// Package sessions implements the telemetry Sessions collector, filling the
// "sessions" section: who is logged in, how (console, RDP, SSH, local
// terminal), and which session — if any — owns the physical console.
//
// Precise login timestamps are deliberately not collected in this first cut:
// the natural source on both Windows (quser) and macOS (who) prints them in
// the host's locale, and parsing that reliably without silently producing a
// wrong date on a non-US-locale install is its own project. Username,
// session type and remote/local status are the P0 ask and are locale-free.
package sessions

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionSessions

// Session describes one logged-in session.
type Session struct {
	Username string `json:"username"`
	// SessionName is the raw platform session identifier: "console",
	// "rdp-tcp#3", "ttys000", a systemd session id, etc.
	SessionName string `json:"session_name,omitempty"`
	// SessionType is a normalised classification: "console", "rdp", "ssh",
	// "terminal", "disconnected", or "other" when the platform reports
	// something this collector does not recognise.
	SessionType string `json:"session_type,omitempty"`
	// Remote is true for a session whose input does not originate at this
	// device's physical console (RDP, SSH, or a systemd session with no seat).
	Remote bool `json:"remote"`
	// State is the platform's own session state string where one exists
	// (e.g. "Active"/"Disc" on Windows, "active"/"online" on Linux). Best
	// effort and platform-dependent; empty when the platform does not report
	// one (macOS's `who` has no state concept).
	State string `json:"state,omitempty"`
}

// Payload is the wire shape of the "sessions" section.
type Payload struct {
	Sessions []Session `json:"sessions"`
	// ConsoleUser is the username holding the physical console session, or
	// empty if nobody is logged in there.
	ConsoleUser string `json:"console_user,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Sessions []Session
	// Err is the real, unclassified error from the platform's enumeration
	// tool, or nil on success. An empty session list is not itself an error —
	// nobody being logged in is a legitimate, common state — so Err is only
	// set when the tool genuinely failed to run or produced unparseable
	// output, never merely because the list came back empty.
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for logged-in sessions.
type Collector struct{}

// New returns the Sessions collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionSessions }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports whether this host has a session-enumeration mechanism
// available at all — see platformCapability in each platform file.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeySessions, platformCapability(ctx)
}

// Collect gathers the current session list.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformSessions(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sessions := sig.Sessions
	sortSessions(sessions)

	payload := Payload{
		Sessions:    sessions,
		ConsoleUser: consoleUser(sessions),
	}

	return payload, *done(sig.Err, sig.Source, len(sessions))
}

// sortSessions orders the list deterministically by username then session
// name, so an unchanged session list hashes identically cycle to cycle —
// Fingerprint's documented requirement for any list payload.
func sortSessions(s []Session) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Username != s[j].Username {
			return s[i].Username < s[j].Username
		}
		return s[i].SessionName < s[j].SessionName
	})
}

// consoleUser returns the username of the session occupying the physical
// console, or "" if none does.
func consoleUser(sessions []Session) string {
	for _, s := range sessions {
		if s.SessionType == "console" {
			return s.Username
		}
	}
	return ""
}
