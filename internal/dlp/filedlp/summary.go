package filedlp

import (
	"sync"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// Summary is what the file channels recorded since the agent started, per
// channel (#430): enough for the backend to chart a pilot ring without
// reading the raw events. Counters are totals since Since, like Stats; the
// backend keeps samples and takes differences, and a newer Since means the
// agent restarted and the totals began again from zero.
type Summary struct {
	Since    time.Time                 `json:"since"`
	Channels map[string]ChannelSummary `json:"channels"`
}

// ChannelSummary counts one file channel's events. An event aggregated over
// several files counts as its repeat_count, as on the console's dashboard.
type ChannelSummary struct {
	// Events is every recorded file, whatever the outcome.
	Events uint64 `json:"events"`
	// Actions counts events by action: monitored, warned, blocked,
	// overridden, quarantined, deleted.
	Actions map[string]uint64 `json:"actions"`
	// WouldHave counts audit-only events by what the agent would have done
	// (blocked, quarantined, deleted, network_blocked): the pilot's
	// would-have-blocked numbers.
	WouldHave map[string]uint64 `json:"would_have"`
	// Remediated is the files quarantined or deleted after they were
	// written (on_close_violation).
	Remediated uint64 `json:"remediated"`
	// Detectors counts events by detector id (an event once per detector it
	// found), to see which detectors drive the would_have numbers. At most
	// maxSummaryDetectors ids per channel; the rest go to DetectorsOther.
	Detectors      map[string]uint64 `json:"detectors"`
	DetectorsOther uint64            `json:"detectors_other,omitempty"`
}

// maxSummaryDetectors caps the detector ids kept per channel, so the status
// stays well under the server's 64 KB limit (4 channels × 50 ids).
const maxSummaryDetectors = 50

// Tally is an event sink that counts the file channels' events (Summary)
// and passes every event on. It is safe for concurrent use.
type Tally struct {
	next  channel.EventSink
	since time.Time

	mu       sync.Mutex
	channels map[string]*ChannelSummary
}

// NewTally returns a Tally that passes events on to next, counting from
// since (the agent's start).
func NewTally(next channel.EventSink, since time.Time) *Tally {
	return &Tally{next: next, since: since.UTC(), channels: map[string]*ChannelSummary{}}
}

// Emit counts ev when it is a file channel's, then passes it on.
func (t *Tally) Emit(ev events.Event) {
	if policy.IsFileChannel(ev.Channel) {
		t.count(ev)
	}
	if t.next != nil {
		t.next.Emit(ev)
	}
}

func (t *Tally) count(ev events.Event) {
	n := uint64(1)
	if ev.RepeatCount > 1 {
		n = uint64(ev.RepeatCount)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.channels[ev.Channel]
	if s == nil {
		s = &ChannelSummary{Actions: map[string]uint64{}, WouldHave: map[string]uint64{}, Detectors: map[string]uint64{}}
		t.channels[ev.Channel] = s
	}
	s.Events += n
	if ev.Action != "" {
		s.Actions[ev.Action] += n
	}
	if ev.WouldHave != "" {
		s.WouldHave[ev.WouldHave] += n
	}
	if ev.Action == events.ActionQuarantined || ev.Action == events.ActionDeleted {
		s.Remediated += n
	}
	seen := map[string]bool{}
	for _, f := range ev.Findings {
		if f.Detector == "" || seen[f.Detector] {
			continue
		}
		seen[f.Detector] = true
		if _, ok := s.Detectors[f.Detector]; ok || len(s.Detectors) < maxSummaryDetectors {
			s.Detectors[f.Detector] += n
		} else {
			s.DetectorsOther += n
		}
	}
}

// Summary returns a copy of the counts so far.
func (t *Tally) Summary() *Summary {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := &Summary{Since: t.since, Channels: make(map[string]ChannelSummary, len(t.channels))}
	for name, s := range t.channels {
		c := *s
		c.Actions = copyCounts(s.Actions)
		c.WouldHave = copyCounts(s.WouldHave)
		c.Detectors = copyCounts(s.Detectors)
		out.Channels[name] = c
	}
	return out
}

func copyCounts(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
