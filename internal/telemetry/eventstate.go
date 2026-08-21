package telemetry

import "time"

// WatchedState is the persisted change-detection state for one watch key.
//
// It holds the last trustworthy value and the bookkeeping that makes debounce,
// cooldown and flap detection survive a restart. Persisting it is what stops an
// agent restart from looking like a first run: without it, every restart would
// re-seed every baseline, and the first real change after each restart would be
// swallowed as "no previous value to compare".
//
// It deliberately stores only the watched value — a scalar or one set member —
// never the section payload it came from.
type WatchedState struct {
	// Key is the watch key, including the "#member" suffix for a membership
	// watch.
	Key string
	// Section is the telemetry section the value came from.
	Section string
	// Value is the last value confirmed trustworthy.
	Value Value
	// ObservedAt is when Value was last seen.
	ObservedAt time.Time
	// ChangedAt is when Value last changed.
	ChangedAt time.Time

	// Pending is a candidate value awaiting confirmation, used by the debounce
	// rule for Normal-priority events. Its Kind is empty when nothing is
	// pending.
	Pending Value
	// PendingSince is when the candidate was first seen. It also becomes the
	// event's occurred_at, so a debounced event is dated when the change
	// actually happened rather than when it was confirmed.
	PendingSince time.Time

	// LastEventAt is when this key last produced an event, for cooldown.
	LastEventAt time.Time

	// FlapCount is how many changes this key has had inside the current
	// flapping window.
	FlapCount int
	// FlapWindowStart opens the current flapping window.
	FlapWindowStart time.Time
	// FlapAlertedAt is when an aggregate flapping event was last emitted, so
	// one unstable value produces one event rather than one per cycle.
	FlapAlertedAt time.Time
}

// HasPending reports whether a candidate value is awaiting confirmation.
func (s *WatchedState) HasPending() bool { return s != nil && s.Pending.Kind != "" }

// ClearPending drops any candidate value.
//
// This is what makes "changed and changed back before confirmation" produce
// zero events: the candidate is discarded without ever having been reported.
func (s *WatchedState) ClearPending() {
	s.Pending = Value{}
	s.PendingSince = time.Time{}
}

// WatchedStateStore persists watched values across cycles and restarts.
//
// The telemetry package depends on this interface rather than the SQLite store
// so the diff engine can be tested against a frozen clock and an in-memory map,
// the same way the cycle logic already is.
type WatchedStateStore interface {
	// GetAll returns every stored watched state, keyed by watch key.
	GetAll() (map[string]*WatchedState, error)
	// Put writes one watched state.
	Put(state *WatchedState) error
	// Delete removes a watch key that is no longer tracked.
	Delete(key string) error
}
