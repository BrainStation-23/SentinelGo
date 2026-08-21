package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

// EventSchemaVersion is the version of the change-event payload shape.
const EventSchemaVersion = models.TelemetryChangeEventSchemaVersion

// EventConfig tunes change detection. Every field has a safe default, so a
// zero value is usable and an existing deployment that has never heard of
// Phase G keeps working.
type EventConfig struct {
	// Debounce is the minimum age of a candidate value before a Normal-priority
	// event is confirmed. Zero means "confirm on the next successful cycle",
	// which is the intended default: one cycle of confirmation is what makes a
	// value that changes and reverts produce nothing at all.
	//
	// Critical and High events are never debounced. Waiting a cycle to report
	// that the firewall went down would be the wrong trade in the one case
	// where latency actually matters.
	Debounce time.Duration
	// Cooldown is the minimum gap between two events for the same watch key.
	Cooldown time.Duration
	// FlapWindow is the period over which repeated changes are counted.
	FlapWindow time.Duration
	// FlapThreshold is how many changes inside FlapWindow make a value
	// "flapping". Once reached, individual events for that key are replaced by
	// a single aggregate event until the window closes.
	FlapThreshold int
}

// Defaults for EventConfig.
const (
	DefaultEventCooldown      = 10 * time.Minute
	DefaultEventFlapWindow    = time.Hour
	DefaultEventFlapThreshold = 4
)

// withDefaults fills in unset fields.
func (c EventConfig) withDefaults() EventConfig {
	if c.Cooldown <= 0 {
		c.Cooldown = DefaultEventCooldown
	}
	if c.FlapWindow <= 0 {
		c.FlapWindow = DefaultEventFlapWindow
	}
	if c.FlapThreshold <= 1 {
		c.FlapThreshold = DefaultEventFlapThreshold
	}
	return c
}

// Validate reports configuration values that cannot work, so a bad config file
// fails at startup rather than producing silently wrong behaviour.
func (c EventConfig) Validate() error {
	if c.Debounce < 0 {
		return fmt.Errorf("telemetry: event debounce must not be negative")
	}
	if c.Cooldown < 0 {
		return fmt.Errorf("telemetry: event cooldown must not be negative")
	}
	if c.FlapWindow < 0 {
		return fmt.Errorf("telemetry: event flapping window must not be negative")
	}
	if c.FlapThreshold < 0 {
		return fmt.Errorf("telemetry: event flapping threshold must not be negative")
	}
	if c.FlapThreshold == 1 {
		return fmt.Errorf("telemetry: event flapping threshold of 1 would classify every single change as flapping")
	}
	if c.FlapWindow > 0 && c.Cooldown > c.FlapWindow {
		return fmt.Errorf("telemetry: event cooldown (%s) exceeds the flapping window (%s), so flapping could never be detected",
			c.Cooldown, c.FlapWindow)
	}
	return nil
}

// EventValue is the narrow before/after payload carried by an event.
//
// It is a fixed, closed struct rather than a free-form map on purpose: it is
// the only thing a change event puts on the wire beyond its own identifiers,
// and a closed struct is what lets a test prove that no section payload, no
// command line and no certificate material can ever leak through here. Adding a
// field means editing this type and the allowlist test together.
type EventValue struct {
	// State is the rendered scalar value ("enabled", "true", a hostname).
	State string `json:"state,omitempty"`
	// Member names the single set member this event is about.
	Member string `json:"member,omitempty"`
	// Count is a set's size, for summary events.
	Count *int `json:"count,omitempty"`
	// Added and Removed are bounded samples of a summary set's delta.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// Changes is the number of changes counted in a flapping window.
	Changes *int `json:"changes,omitempty"`
}

// EventEnvelope is the wire format for the change-event RPC.
//
// It is a separate envelope from the section Envelope because the two go to
// different backend endpoints with different retention and different meaning.
// Sharing one shape would put change events through section reconciliation,
// which they must never touch.
type EventEnvelope struct {
	SchemaVersion int                           `json:"schema_version"`
	DeviceID      string                        `json:"device_id"`
	AgentVersion  string                        `json:"agent_version,omitempty"`
	Platform      string                        `json:"platform"`
	Events        []models.TelemetryChangeEvent `json:"events"`
}

// EventID derives the deterministic identity of one change event.
//
// The inputs are exactly device, type, watch key and occurrence time, so the
// same change computed twice yields the same id. That is what makes delivery
// idempotent: a retry after a lost response replays the stored bytes, the
// backend sees an event_id it already has, and `on conflict do nothing` drops
// the duplicate. No second deduplication database is needed on either side.
func EventID(deviceID, eventType, watchKey, occurredAt string) string {
	h := sha256.New()
	// The separator is a byte that cannot appear in any of the inputs, so
	// ("a|b", "c") and ("a", "b|c") cannot collide.
	for _, part := range []string{deviceID, eventType, watchKey, occurredAt} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EventEngine turns already-collected section data into change events.
//
// It performs NO collection of its own. Every value it compares comes from the
// cycle that just ran, so on a stable endpoint the engine costs one JSON
// re-encode per watched section and nothing else.
type EventEngine struct {
	watches []Watch
	store   WatchedStateStore
	cfg     EventConfig
	now     func() time.Time
}

// NewEventEngine builds an engine. A nil store is allowed for tests and makes
// the engine stateless (every cycle looks like a first observation, so nothing
// is ever emitted) rather than panicking.
func NewEventEngine(watches []Watch, store WatchedStateStore, cfg EventConfig) *EventEngine {
	if watches == nil {
		watches = DefaultWatches()
	}
	return &EventEngine{
		watches: watches,
		store:   store,
		cfg:     cfg.withDefaults(),
		now:     time.Now,
	}
}

// SetClock overrides the time source. Intended for tests.
func (e *EventEngine) SetClock(fn func() time.Time) {
	if fn != nil {
		e.now = fn
	}
}

// Watches exposes the configured watches, for the CLI and tests.
func (e *EventEngine) Watches() []Watch { return e.watches }

// EventResult is one cycle's change-detection outcome.
type EventResult struct {
	Events []models.TelemetryChangeEvent
	// Seeded lists watch keys whose baseline was established this cycle. A
	// seeded key produces no event by definition.
	Seeded []string
	// Suppressed lists watch keys whose transition was real but withheld —
	// awaiting debounce confirmation, inside a cooldown, or flapping.
	Suppressed []string
	// SkippedSections lists sections that were not eligible this cycle because
	// they did not collect successfully.
	SkippedSections []string
}

// Process compares this cycle's data against the stored baseline.
//
// statuses maps section name to the collector status from this cycle. A section
// is only eligible when it reports StatusSuccess. That rule is deliberately
// strict and is the core safety property of the whole feature:
//
//   - An error, timeout, permission_denied or unsupported result means the
//     agent does not know the current value. Comparing against "nothing" would
//     read as "the firewall disappeared", which is a critical alert generated
//     by a failed query rather than by anything happening on the device.
//   - StatusPartial is excluded for the same reason at set granularity: a
//     partial read of the administrators group cannot be distinguished from
//     accounts having been removed.
//   - An ineligible section leaves its watched values untouched, so the last
//     GOOD value survives the outage and the next successful cycle compares
//     against reality rather than against a gap.
func (e *EventEngine) Process(deviceID, agentVersion string, data SectionData, statuses map[string]Status) (*EventResult, error) {
	result := &EventResult{}
	now := e.now().UTC()

	stored, err := e.loadState()
	if err != nil {
		return nil, err
	}

	documents := make(map[string]any)

	for _, w := range e.watches {
		if statuses[w.Section] != StatusSuccess {
			if !containsString(result.SkippedSections, w.Section) {
				result.SkippedSections = append(result.SkippedSections, w.Section)
			}
			continue
		}
		payload, ok := data[w.Section]
		if !ok {
			if !containsString(result.SkippedSections, w.Section) {
				result.SkippedSections = append(result.SkippedSections, w.Section)
			}
			continue
		}

		doc, docErr := documentFor(documents, w.Section, payload)
		if docErr != nil {
			// A section that cannot be re-encoded is a bug, not a device
			// state. Skip it rather than let it look like a change.
			continue
		}

		current, trustworthy := w.Extract(doc)
		if !trustworthy {
			continue
		}

		if err := e.evaluate(w, current, stored, deviceID, now, result); err != nil {
			return nil, err
		}
	}

	stampEnvelopeFields(result.Events, deviceID, agentVersion)
	sortEvents(result.Events)
	return result, nil
}

// evaluate applies one watch's comparison and updates its stored state.
func (e *EventEngine) evaluate(w Watch, current Value, stored map[string]*WatchedState, deviceID string, now time.Time, result *EventResult) error {
	switch w.Kind {
	case KindMembership:
		return e.evaluateMembership(w, current, stored, deviceID, now, result)
	default:
		return e.evaluateKey(w, w.Key, current, stored, deviceID, now, result, w.transitionFor)
	}
}

// evaluateMembership diffs a membership set and reports each member's arrival
// or departure as its own event.
//
// The set as a whole is stored under the watch's base key; individual members
// get a row only once they have actually changed. That split is what makes
// "alice was added" and "bob was added" in one cycle two events with different
// ids, each with its own cooldown and flap history, without keeping a row per
// administrator account on every device forever.
//
// The base key is also the seeding marker. Deciding "is this member new?" from
// the presence of a per-member row instead would make every account added after
// the baseline look like a first observation and be silently seeded — which is
// precisely the change that most needs reporting.
func (e *EventEngine) evaluateMembership(w Watch, current Value, stored map[string]*WatchedState, deviceID string, now time.Time, result *EventResult) error {
	base, exists := stored[w.Key]
	if !exists {
		seeded := &WatchedState{
			Key:        w.Key,
			Section:    w.Section,
			Value:      current,
			ObservedAt: now,
			ChangedAt:  now,
		}
		stored[w.Key] = seeded
		result.Seeded = append(result.Seeded, w.Key)
		return e.put(seeded)
	}

	previous := base.Value
	added, removed := setDelta(previous, current)

	changed := make([]string, 0, len(added)+len(removed))
	changed = append(changed, added...)
	changed = append(changed, removed...)
	sort.Strings(changed)

	for _, member := range changed {
		key := MembershipKey(w.Key, member)

		// A member that has never changed before has no row yet. Create it
		// holding the PREVIOUS presence, so the comparison below is a real
		// transition rather than a first observation.
		if _, ok := stored[key]; !ok {
			stored[key] = &WatchedState{
				Key:        key,
				Section:    w.Section,
				Value:      BoolValue(previous.Has(member)),
				ObservedAt: now,
				ChangedAt:  now,
			}
		}

		classify := func(from, to Value) (string, string) {
			switch {
			case to.Scalar == "true" && from.Scalar == "false":
				return w.AddedEvent, member
			case to.Scalar == "false" && from.Scalar == "true":
				return w.RemovedEvent, member
			default:
				return "", member
			}
		}

		present := BoolValue(current.Has(member))
		if err := e.evaluateKey(w, key, present, stored, deviceID, now, result, classify); err != nil {
			return err
		}
	}

	// Commit the set itself last, so a failure above leaves the previous
	// membership intact and the same delta is recomputed next cycle rather than
	// being lost.
	base.Value = current
	base.ObservedAt = now
	if len(changed) > 0 {
		base.ChangedAt = now
	}
	return e.put(base)
}

// transitionFor maps a scalar or summary change onto an event type.
func (w Watch) transitionFor(from, to Value) (eventType, member string) {
	if w.Kind == KindSetSummary {
		// A summary set reports one event for the cycle's whole delta, so the
		// direction of individual members does not select the type.
		added, removed := setDelta(from, to)
		switch {
		case len(added) > 0 && w.AddedEvent != "":
			return w.AddedEvent, ""
		case len(removed) > 0 && w.RemovedEvent != "":
			return w.RemovedEvent, ""
		default:
			return "", ""
		}
	}

	for _, t := range w.Transitions {
		if t.From != "" && t.From != from.Scalar {
			continue
		}
		if t.To != "" && t.To != to.Scalar {
			continue
		}
		return t.EventType, ""
	}
	return "", ""
}

// evaluateKey runs the full state machine for one concrete watch key.
func (e *EventEngine) evaluateKey(
	w Watch,
	key string,
	current Value,
	stored map[string]*WatchedState,
	deviceID string,
	now time.Time,
	result *EventResult,
	classify func(from, to Value) (eventType, member string),
) error {
	state, exists := stored[key]

	// First observation: seed the baseline and report nothing.
	//
	// This is not an optimisation. Without it, provisioning a fleet would
	// generate a "firewall_disabled" for every device that happens to be in
	// that state, plus one event per existing administrator account, on the
	// first cycle after deployment — a synthetic incident on day one.
	if !exists {
		seeded := &WatchedState{
			Key:        key,
			Section:    w.Section,
			Value:      current,
			ObservedAt: now,
			ChangedAt:  now,
		}
		stored[key] = seeded
		result.Seeded = append(result.Seeded, key)
		return e.put(seeded)
	}

	if current.Equal(state.Value) {
		// Unchanged. Drop any candidate: a value that moved and moved back
		// before confirmation must produce nothing at all.
		if state.HasPending() {
			state.ClearPending()
			result.Suppressed = append(result.Suppressed, key)
		}
		state.ObservedAt = now
		return e.put(state)
	}

	previous := state.Value
	eventType, member := classify(previous, current)

	// A change with no mapped event type still has to be recorded, or every
	// subsequent cycle would rediscover it.
	if eventType == "" {
		e.commit(state, current, now)
		return e.put(state)
	}

	priority := models.PriorityForEventType(eventType)

	// Normal-priority changes wait one successful cycle before being believed.
	if priority == models.PriorityNormal && !e.confirmed(state, current, now) {
		// The clock restarts whenever the CANDIDATE itself changes, not just
		// when there was none. A value that walks A -> B -> C must not confirm
		// C using the timestamp B was first seen at; that would report a change
		// the device only briefly passed through.
		if !state.HasPending() || !state.Pending.Equal(current) {
			state.PendingSince = now
		}
		state.Pending = current
		result.Suppressed = append(result.Suppressed, key)
		return e.put(state)
	}

	// occurred_at is when the new value was FIRST seen, which for a debounced
	// event is an earlier cycle than the one confirming it. Reporting the
	// confirmation time instead would misdate every Normal event by a full
	// collection interval.
	occurredAt := now
	if priority == models.PriorityNormal && !state.PendingSince.IsZero() {
		occurredAt = state.PendingSince
	}

	flapping := e.recordChange(state, now)

	switch {
	case flapping:
		if evt, emit := e.flapEvent(w, key, state, deviceID, now); emit {
			result.Events = append(result.Events, evt)
			state.LastEventAt = now
			state.FlapAlertedAt = now
		} else {
			result.Suppressed = append(result.Suppressed, key)
		}

	case e.inCooldown(state, now):
		result.Suppressed = append(result.Suppressed, key)

	default:
		result.Events = append(result.Events, buildEvent(
			deviceID, eventType, key, w.Section, member, previous, current, occurredAt, now))
		state.LastEventAt = now
	}

	e.commit(state, current, now)
	return e.put(state)
}

// confirmed reports whether a pending candidate has waited long enough.
//
// The default (Debounce == 0) requires the candidate to have been recorded in
// an EARLIER cycle, which is the "one successful cycle" rule: the first sighting
// only records the candidate, the second confirms it.
func (e *EventEngine) confirmed(state *WatchedState, current Value, now time.Time) bool {
	if !state.HasPending() || !state.Pending.Equal(current) {
		return false
	}
	if e.cfg.Debounce == 0 {
		return now.After(state.PendingSince)
	}
	return now.Sub(state.PendingSince) >= e.cfg.Debounce
}

// inCooldown reports whether this key emitted an event too recently.
func (e *EventEngine) inCooldown(state *WatchedState, now time.Time) bool {
	if state.LastEventAt.IsZero() || e.cfg.Cooldown <= 0 {
		return false
	}
	return now.Sub(state.LastEventAt) < e.cfg.Cooldown
}

// recordChange advances the flapping counter and reports whether the key has
// crossed the threshold.
func (e *EventEngine) recordChange(state *WatchedState, now time.Time) bool {
	if e.cfg.FlapWindow <= 0 || e.cfg.FlapThreshold <= 1 {
		return false
	}
	if state.FlapWindowStart.IsZero() || now.Sub(state.FlapWindowStart) >= e.cfg.FlapWindow {
		state.FlapWindowStart = now
		state.FlapCount = 0
		state.FlapAlertedAt = time.Time{}
	}
	state.FlapCount++
	return state.FlapCount >= e.cfg.FlapThreshold
}

// flapEvent builds the aggregate event, or reports that one has already been
// sent for the current window.
func (e *EventEngine) flapEvent(w Watch, key string, state *WatchedState, deviceID string, now time.Time) (models.TelemetryChangeEvent, bool) {
	if !state.FlapAlertedAt.IsZero() {
		return models.TelemetryChangeEvent{}, false
	}

	changes := state.FlapCount
	occurredAt := state.FlapWindowStart
	if occurredAt.IsZero() {
		occurredAt = now
	}

	evt := newEvent(deviceID, models.EventStateFlapping, key, w.Section, occurredAt, now)
	evt.PreviousValue = &EventValue{State: state.Value.Scalar}
	evt.CurrentValue = &EventValue{Changes: &changes}
	return evt, true
}

// commit records the new value as the accepted baseline.
func (e *EventEngine) commit(state *WatchedState, current Value, now time.Time) {
	state.Value = current
	state.ObservedAt = now
	state.ChangedAt = now
	state.ClearPending()
}

func (e *EventEngine) put(state *WatchedState) error {
	if e.store == nil {
		return nil
	}
	if err := e.store.Put(state); err != nil {
		return fmt.Errorf("telemetry: persist watched state %q: %w", state.Key, err)
	}
	return nil
}

func (e *EventEngine) loadState() (map[string]*WatchedState, error) {
	if e.store == nil {
		return map[string]*WatchedState{}, nil
	}
	stored, err := e.store.GetAll()
	if err != nil {
		return nil, fmt.Errorf("telemetry: read watched state: %w", err)
	}
	if stored == nil {
		stored = map[string]*WatchedState{}
	}
	return stored, nil
}

// buildEvent assembles one change event with its narrow before/after values.
func buildEvent(deviceID, eventType, watchKey, section, member string, previous, current Value, occurredAt, detectedAt time.Time) models.TelemetryChangeEvent {
	evt := newEvent(deviceID, eventType, watchKey, section, occurredAt, detectedAt)

	switch current.Kind {
	case KindSetSummary:
		added, removed := setDelta(previous, current)
		prevCount, curCount := len(previous.Members), len(current.Members)
		evt.PreviousValue = &EventValue{Count: &prevCount}
		evt.CurrentValue = &EventValue{
			Count:   &curCount,
			Added:   boundedSample(added),
			Removed: boundedSample(removed),
		}
	default:
		evt.PreviousValue = &EventValue{State: previous.Scalar, Member: member}
		evt.CurrentValue = &EventValue{State: current.Scalar, Member: member}
	}
	return evt
}

// newEvent fills the identity and timing fields shared by every event.
func newEvent(deviceID, eventType, watchKey, section string, occurredAt, detectedAt time.Time) models.TelemetryChangeEvent {
	occurred := occurredAt.UTC().Format(time.RFC3339)
	return models.TelemetryChangeEvent{
		EventID:       EventID(deviceID, eventType, watchKey, occurred),
		EventType:     eventType,
		Section:       section,
		Priority:      models.PriorityForEventType(eventType),
		Severity:      models.SeverityForEventType(eventType),
		OccurredAt:    occurred,
		DetectedAt:    detectedAt.UTC().Format(time.RFC3339),
		SchemaVersion: EventSchemaVersion,
	}
}

// setDelta returns the members added and removed between two set values.
func setDelta(previous, current Value) (added, removed []string) {
	prev := make(map[string]struct{}, len(previous.Members))
	for _, m := range previous.Members {
		prev[m] = struct{}{}
	}
	cur := make(map[string]struct{}, len(current.Members))
	for _, m := range current.Members {
		cur[m] = struct{}{}
	}

	for _, m := range current.Members {
		if _, had := prev[m]; !had {
			added = append(added, m)
		}
	}
	for _, m := range previous.Members {
		if _, still := cur[m]; !still {
			removed = append(removed, m)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// boundedSample caps a delta list so one large change cannot produce an
// unbounded event payload.
func boundedSample(items []string) []string {
	if len(items) <= maxSetSummarySampleLength {
		return items
	}
	return items[:maxSetSummarySampleLength]
}

// documentFor re-encodes a section payload as a generic JSON document, caching
// the result so a section watched by several watches is encoded once.
func documentFor(cache map[string]any, section string, payload any) (any, error) {
	if doc, ok := cache[section]; ok {
		return doc, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("telemetry: encode section %q for change detection: %w", section, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("telemetry: decode section %q for change detection: %w", section, err)
	}
	cache[section] = doc
	return doc, nil
}

// stampEnvelopeFields is a no-op placeholder kept explicit: the envelope, not
// the event, carries device and agent identity, so nothing per-event needs
// stamping. Keeping the call site makes that a stated decision rather than an
// omission someone later "fixes" by duplicating the device id onto every event.
func stampEnvelopeFields(_ []models.TelemetryChangeEvent, _, _ string) {}

// sortEvents orders events most-urgent-first, then by type and id, so a cycle
// produces a deterministic sequence regardless of map iteration order.
func sortEvents(events []models.TelemetryChangeEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Priority != events[j].Priority {
			return events[i].Priority < events[j].Priority
		}
		if events[i].EventType != events[j].EventType {
			return events[i].EventType < events[j].EventType
		}
		return events[i].EventID < events[j].EventID
	})
}

// StatusesFrom indexes a cycle's collector results by section.
func StatusesFrom(results []CollectorResult) map[string]Status {
	out := make(map[string]Status, len(results))
	for _, r := range results {
		out[r.Section] = r.Status
	}
	return out
}

// SummarizeEvents renders a one-line description of a cycle's events, for logs.
func SummarizeEvents(events []models.TelemetryChangeEvent) string {
	if len(events) == 0 {
		return "none"
	}
	counts := make(map[string]int, len(events))
	for _, e := range events {
		counts[e.EventType]++
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, fmt.Sprintf("%s=%d", t, counts[t]))
	}
	sort.Strings(types)
	return strings.Join(types, " ")
}
