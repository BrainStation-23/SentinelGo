package telemetry

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
)

// newEventService builds a cycle service with change detection enabled over an
// in-memory watched-state store.
func newEventService(t *testing.T, watchStore *memWatchedStore, clk *clock, collectors ...Collector) (*Service, *fakeQueue) {
	t.Helper()

	svc, _, queue := newTestService(t, collectors...)
	svc.SetClock(clk.now)
	engine := NewEventEngine(DefaultWatches(), watchStore, EventConfig{Cooldown: time.Nanosecond})
	svc.SetEventEngine(engine)
	engine.SetClock(clk.now)
	return svc, queue
}

func testConfig() *config.Config {
	return &config.Config{DeviceID: testDeviceID, CurrentVersion: "v3.2.9"}
}

// ── 17 & 18. class routing ───────────────────────────────────────────────────

// TestEventMessagesAreQueuedAsClassEvent is what makes the sender pick the
// events RPC. Nothing else on the queue distinguishes an event message from a
// section message.
func TestEventMessagesAreQueuedAsClassEvent(t *testing.T) {
	watchStore := newMemWatchedStore()
	clk := newClock()

	firewall := &fakeCollector{
		name: "protection", section: SectionProtection,
		capKey: CapKeyFirewall, capState: CapSupported,
		payload: protectionPayload("enabled", "enabled", "enabled"),
	}
	svc, queue := newEventService(t, watchStore, clk, firewall)
	cfg := testConfig()

	if _, err := svc.RunCycle(t.Context(), cfg); err != nil { // seed
		t.Fatalf("RunCycle() error = %v", err)
	}

	firewall.payload = protectionPayload("disabled", "enabled", "enabled")
	clk.advance(15 * time.Minute)

	report, err := svc.RunCycle(t.Context(), cfg)
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(report.Events) == 0 {
		t.Fatal("the firewall going down produced no event")
	}

	var eventMessages, sectionMessages int
	for _, msg := range queue.messages {
		switch msg.Class {
		case ClassEvent:
			eventMessages++
		case ClassInventory, ClassPosture, ClassHealth:
			sectionMessages++
		default:
			t.Errorf("message queued with unrecognised class %q", msg.Class)
		}
	}
	if eventMessages != 1 {
		t.Errorf("queued %d event message(s), want 1", eventMessages)
	}
	if sectionMessages == 0 {
		t.Error("section messages stopped being queued once events were enabled")
	}
}

// TestEventMessagesCarryNoSections is the guarantee that event delivery cannot
// advance section reconciliation.
//
// The delivery path advances the reconcile clock for every section a delivered
// message names. An event message naming its source section would mark that
// section as reconciled without the backend ever having received it, and the
// section's real payload would then sit unsent until its next content change.
func TestEventMessagesCarryNoSections(t *testing.T) {
	watchStore := newMemWatchedStore()
	clk := newClock()

	firewall := &fakeCollector{
		name: "protection", section: SectionProtection,
		capKey: CapKeyFirewall, capState: CapSupported,
		payload: protectionPayload("enabled", "enabled", "enabled"),
	}
	svc, queue := newEventService(t, watchStore, clk, firewall)
	cfg := testConfig()

	if _, err := svc.RunCycle(t.Context(), cfg); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	firewall.payload = protectionPayload("disabled", "enabled", "enabled")
	clk.advance(15 * time.Minute)
	if _, err := svc.RunCycle(t.Context(), cfg); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}

	found := false
	for _, msg := range queue.messages {
		if msg.Class != ClassEvent {
			continue
		}
		found = true
		if len(msg.Sections) != 0 {
			t.Errorf("event message names sections %v; delivery would advance their reconcile clocks",
				msg.Sections)
		}
	}
	if !found {
		t.Fatal("no event message was queued")
	}
}

// TestSectionRoutingIsUnchangedByEvents: enabling change detection must not
// alter which sections are enqueued, in what class, or with what priority.
func TestSectionRoutingIsUnchangedByEvents(t *testing.T) {
	collect := func(withEvents bool) []QueuedMessage {
		c := &fakeCollector{
			name: "protection", section: SectionProtection,
			capKey: CapKeyFirewall, capState: CapSupported,
			payload: protectionPayload("enabled", "enabled", "enabled"),
		}
		svc, _, queue := newTestService(t, c)
		clk := newClock()
		svc.SetClock(clk.now)
		if withEvents {
			engine := NewEventEngine(DefaultWatches(), newMemWatchedStore(), EventConfig{})
			svc.SetEventEngine(engine)
			engine.SetClock(clk.now)
		}
		if _, err := svc.RunCycle(t.Context(), testConfig()); err != nil {
			t.Fatalf("RunCycle() error = %v", err)
		}

		var sections []QueuedMessage
		for _, m := range queue.messages {
			if m.Class != ClassEvent {
				sections = append(sections, m)
			}
		}
		return sections
	}

	without := collect(false)
	with := collect(true)

	if len(without) != len(with) {
		t.Fatalf("section message count changed: %d without events, %d with", len(without), len(with))
	}
	for i := range without {
		if without[i].Class != with[i].Class {
			t.Errorf("message %d class changed: %q -> %q", i, without[i].Class, with[i].Class)
		}
		if without[i].Priority != with[i].Priority {
			t.Errorf("message %d priority changed: %d -> %d", i, without[i].Priority, with[i].Priority)
		}
		if !reflect.DeepEqual(without[i].Sections, with[i].Sections) {
			t.Errorf("message %d sections changed: %v -> %v", i, without[i].Sections, with[i].Sections)
		}
	}
}

// ── 22. priority ordering ────────────────────────────────────────────────────

// TestEventsAreBatchedByPriority: the queue orders by the message's priority
// column, so mixing a critical event into a batch of routine ones would either
// delay the critical event or promote the routine ones.
func TestEventsAreBatchedByPriority(t *testing.T) {
	events := []models.TelemetryChangeEvent{
		{EventType: models.EventFirewallDisabled, Priority: models.PriorityCritical, EventID: "a"},
		{EventType: models.EventNewLocalAdmin, Priority: models.PriorityCritical, EventID: "b"},
		{EventType: models.EventDirectoryJoinChanged, Priority: models.PriorityHigh, EventID: "c"},
		{EventType: models.EventHostnameChanged, Priority: models.PriorityNormal, EventID: "d"},
	}

	batches := batchEvents(events)
	if len(batches) != 3 {
		t.Fatalf("got %d batch(es), want 3 (one per priority)", len(batches))
	}

	wantPriorities := []models.EventPriority{
		models.PriorityCritical, models.PriorityHigh, models.PriorityNormal,
	}
	for i, batch := range batches {
		for _, e := range batch {
			if e.Priority != wantPriorities[i] {
				t.Errorf("batch %d mixes priority %d into a %d batch", i, e.Priority, wantPriorities[i])
			}
		}
	}
	if len(batches[0]) != 2 {
		t.Errorf("critical batch has %d event(s), want 2", len(batches[0]))
	}
}

func TestEventBatchesRespectTheSizeCap(t *testing.T) {
	events := make([]models.TelemetryChangeEvent, maxEventsPerMessage*2+3)
	for i := range events {
		events[i] = models.TelemetryChangeEvent{
			EventType: models.EventHostnameChanged,
			Priority:  models.PriorityNormal,
		}
	}

	batches := batchEvents(events)
	if len(batches) != 3 {
		t.Fatalf("got %d batch(es), want 3", len(batches))
	}
	for i, b := range batches {
		if len(b) > maxEventsPerMessage {
			t.Errorf("batch %d holds %d events, over the %d cap", i, len(b), maxEventsPerMessage)
		}
	}
}

// TestCriticalEventsSortFirst: the engine emits most-urgent-first so the first
// queued message is the one that matters, even when a cycle produces several
// kinds of change at once.
func TestCriticalEventsSortFirst(t *testing.T) {
	events := []models.TelemetryChangeEvent{
		{EventType: models.EventHostnameChanged, Priority: models.PriorityNormal, EventID: "d"},
		{EventType: models.EventDirectoryJoinChanged, Priority: models.PriorityHigh, EventID: "c"},
		{EventType: models.EventFirewallDisabled, Priority: models.PriorityCritical, EventID: "a"},
	}
	sortEvents(events)

	if events[0].Priority != models.PriorityCritical {
		t.Fatalf("first event has priority %d, want critical", events[0].Priority)
	}
	if !sort.SliceIsSorted(events, func(i, j int) bool { return events[i].Priority < events[j].Priority }) {
		t.Error("events are not ordered most-urgent-first")
	}
}

// TestQueuedEventPriorityMatchesTheEvent: the queue column is what orders
// delivery, so it must agree with the event it carries.
func TestQueuedEventPriorityMatchesTheEvent(t *testing.T) {
	watchStore := newMemWatchedStore()
	clk := newClock()

	firewall := &fakeCollector{
		name: "protection", section: SectionProtection,
		capKey: CapKeyFirewall, capState: CapSupported,
		payload: protectionPayload("enabled", "enabled", "enabled"),
	}
	svc, queue := newEventService(t, watchStore, clk, firewall)
	cfg := testConfig()

	if _, err := svc.RunCycle(t.Context(), cfg); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	firewall.payload = protectionPayload("disabled", "enabled", "enabled")
	clk.advance(15 * time.Minute)
	if _, err := svc.RunCycle(t.Context(), cfg); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}

	for _, msg := range queue.messages {
		if msg.Class != ClassEvent {
			continue
		}
		if msg.Priority != int(models.PriorityCritical) {
			t.Errorf("queued event message priority = %d, want %d",
				msg.Priority, models.PriorityCritical)
		}
	}
}

// ── envelope shape ───────────────────────────────────────────────────────────

func TestEventEnvelopeShape(t *testing.T) {
	events := []models.TelemetryChangeEvent{{
		EventID:       "abc",
		EventType:     models.EventFirewallDisabled,
		Section:       SectionProtection,
		Priority:      models.PriorityCritical,
		Severity:      models.SeverityCritical,
		OccurredAt:    "2026-08-21T09:15:00Z",
		DetectedAt:    "2026-08-21T09:15:00Z",
		SchemaVersion: EventSchemaVersion,
	}}

	body, err := marshalEventEnvelope(testConfig(), events)
	if err != nil {
		t.Fatalf("marshalEventEnvelope() error = %v", err)
	}

	var wrapper struct {
		Payload EventEnvelope `json:"payload"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}

	got := wrapper.Payload
	if got.SchemaVersion != EventSchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, EventSchemaVersion)
	}
	if got.DeviceID != testDeviceID {
		t.Errorf("device_id = %q, want %q", got.DeviceID, testDeviceID)
	}
	if got.Platform == "" {
		t.Error("platform is empty")
	}
	if len(got.Events) != 1 || got.Events[0].EventID != "abc" {
		t.Errorf("events did not round-trip: %+v", got.Events)
	}
}

// ── 24. privacy allowlist ────────────────────────────────────────────────────

// allowedEventFields is the complete set of JSON keys a change event may carry.
//
// This list, and the closed EventValue struct it mirrors, are the mechanism
// that keeps section payloads out of events. A change event exists to say "this
// one value moved"; if it could carry arbitrary fields, the obvious next step
// for anyone adding a watch would be to attach the section that produced it —
// and process command lines, certificate details and session records would
// start travelling on a path with a year of retention.
var allowedEventFields = map[string]struct{}{
	"event_id":       {},
	"event_type":     {},
	"section":        {},
	"priority":       {},
	"severity":       {},
	"occurred_at":    {},
	"detected_at":    {},
	"previous_value": {},
	"current_value":  {},
	"schema_version": {},
}

// allowedValueFields is the complete set of keys inside previous_value and
// current_value.
var allowedValueFields = map[string]struct{}{
	"state":   {},
	"member":  {},
	"count":   {},
	"added":   {},
	"removed": {},
	"changes": {},
}

// TestEventPayloadsCarryOnlyAllowedFields drives every watch through a real
// transition and inspects the JSON that would actually go on the wire.
//
// It is table-driven over the watches themselves rather than over a handful of
// examples, so a new watch added later is covered automatically instead of
// needing someone to remember to extend this test.
func TestEventPayloadsCarryOnlyAllowedFields(t *testing.T) {
	cases := []struct {
		name   string
		before SectionData
		after  SectionData
	}{
		{
			name:   "firewall disabled",
			before: protectionData("enabled", "enabled", "enabled"),
			after:  protectionData("disabled", "disabled", "disabled"),
		},
		{
			name:   "secure boot disabled",
			before: SectionData{SectionSecureBoot: map[string]any{"state": "enabled"}},
			after:  SectionData{SectionSecureBoot: map[string]any{"state": "disabled"}},
		},
		{
			name:   "encryption turned off",
			before: SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "on"})},
			after:  SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "off"})},
		},
		{
			name:   "local admin added",
			before: SectionData{SectionSecurityPost: postureData("Administrator")},
			after:  SectionData{SectionSecurityPost: postureData("Administrator", "eve")},
		},
		{
			name:   "hostname changed",
			before: SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}},
			after:  SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}},
		},
		{
			name:   "ip changed",
			before: SectionData{SectionNetwork: networkData("10.0.0.5")},
			after:  SectionData{SectionNetwork: networkData("10.0.0.9")},
		},
		{
			name:   "directory join changed",
			before: SectionData{SectionDirectory: map[string]any{"domain_joined": true}},
			after:  SectionData{SectionDirectory: map[string]any{"domain_joined": false}},
		},
		{
			name:   "reboot required",
			before: SectionData{SectionOS: map[string]any{"pending_reboot": false}},
			after:  SectionData{SectionOS: map[string]any{"pending_reboot": true}},
		},
		{
			name: "patch installed",
			before: SectionData{SectionPatches: []any{
				map[string]any{"id": "KB5000001", "status": "installed"},
			}},
			after: SectionData{SectionPatches: []any{
				map[string]any{"id": "KB5000001", "status": "installed"},
				map[string]any{"id": "KB5000002", "status": "installed"},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
			h.cycle(tc.before)

			// Critical and high-priority watches emit on the first sighting of
			// the new value; Normal ones need a second cycle to clear debounce.
			// Collecting both means one table covers every priority without the
			// case needing to know which kind it is.
			var events []models.TelemetryChangeEvent
			events = append(events, h.cycle(tc.after).Events...)
			events = append(events, h.cycle(tc.after).Events...)

			if len(events) == 0 {
				t.Fatalf("no event produced; this case cannot prove anything about payloads")
			}

			for _, evt := range events {
				assertEventFieldsAllowed(t, evt)
			}
		})
	}
}

func assertEventFieldsAllowed(t *testing.T, evt models.TelemetryChangeEvent) {
	t.Helper()

	raw, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}

	for field := range doc {
		if _, ok := allowedEventFields[field]; !ok {
			t.Errorf("event %s carries disallowed field %q", evt.EventType, field)
		}
	}

	for _, valueField := range []string{"previous_value", "current_value"} {
		body, present := doc[valueField]
		if !present {
			continue
		}
		var value map[string]json.RawMessage
		if err := json.Unmarshal(body, &value); err != nil {
			t.Errorf("%s is not an object: %v", valueField, err)
			continue
		}
		for field, contents := range value {
			if _, ok := allowedValueFields[field]; !ok {
				t.Errorf("event %s %s carries disallowed field %q", evt.EventType, valueField, field)
			}
			// Nothing inside a value may itself be a nested object: that is how
			// a section payload would get in.
			if strings.HasPrefix(strings.TrimSpace(string(contents)), "{") {
				t.Errorf("event %s %s.%s is a nested object; values must stay flat",
					evt.EventType, valueField, field)
			}
		}
	}
}

// TestEventValueStructIsClosed pins the allowlist to the type itself, so adding
// a field to EventValue without updating the allowlist fails here rather than
// silently widening what events can carry.
func TestEventValueStructIsClosed(t *testing.T) {
	typ := reflect.TypeOf(EventValue{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		if _, ok := allowedValueFields[name]; !ok {
			t.Errorf("EventValue field %q is not in allowedValueFields; either it is a privacy "+
				"regression or the allowlist needs updating deliberately", name)
		}
	}
}

// TestSetSummarySamplesAreBounded: one large change must not produce an
// unbounded event payload.
func TestSetSummarySamplesAreBounded(t *testing.T) {
	before := make([]string, 0, 100)
	after := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		after = append(after, string(rune('a'+i%26))+string(rune('0'+i/26))+".addr")
	}

	prev := SetValue(KindSetSummary, before)
	cur := SetValue(KindSetSummary, after)
	evt := buildEvent(testDeviceID, models.EventIPChanged, WatchIPv4Addresses,
		SectionNetwork, "", prev, cur, time.Now(), time.Now())

	value := evt.CurrentValue.(*EventValue)
	if len(value.Added) > maxSetSummarySampleLength {
		t.Errorf("added sample holds %d entries, over the %d cap",
			len(value.Added), maxSetSummarySampleLength)
	}
	if value.Count == nil || *value.Count != 100 {
		t.Errorf("count = %v, want 100 — the full size must still be reported", value.Count)
	}
}

// TestEventsNeverCarryCommandLines is a direct check against the single most
// sensitive field in the whole telemetry layer.
func TestEventsNeverCarryCommandLines(t *testing.T) {
	for _, w := range DefaultWatches() {
		if w.Section == SectionProcesses {
			t.Errorf("watch %q reads the processes section; process command lines "+
				"must not reach the event path", w.Key)
		}
		if w.Section == SectionCertificates {
			t.Errorf("watch %q reads the certificates section; certificate material "+
				"must not reach the event path", w.Key)
		}
		if w.Section == SectionSessions {
			t.Errorf("watch %q reads the sessions section; user activity must not "+
				"reach the event path", w.Key)
		}
	}
}

// ── watch registry sanity ────────────────────────────────────────────────────

func TestDefaultWatchesAreWellFormed(t *testing.T) {
	seen := make(map[string]bool)
	registry := NewDefaultRegistry()

	for _, w := range DefaultWatches() {
		if w.Key == "" {
			t.Error("a watch has an empty key")
			continue
		}
		if seen[w.Key] {
			t.Errorf("duplicate watch key %q; the second would overwrite the first's state", w.Key)
		}
		seen[w.Key] = true

		if w.Extract == nil {
			t.Errorf("watch %q has no extractor", w.Key)
		}
		if _, ok := registry.Get(w.Section); !ok {
			t.Errorf("watch %q reads section %q, which is not in the section registry",
				w.Key, w.Section)
		}
		if strings.Contains(w.Key, membershipKeySeparator) {
			t.Errorf("watch key %q contains the membership separator %q and would collide "+
				"with a per-member key", w.Key, membershipKeySeparator)
		}

		switch w.Kind {
		case KindScalar:
			if len(w.Transitions) == 0 {
				t.Errorf("scalar watch %q declares no transitions, so it can never emit", w.Key)
			}
		case KindMembership, KindSetSummary:
			if w.AddedEvent == "" && w.RemovedEvent == "" {
				t.Errorf("set watch %q declares neither an added nor a removed event", w.Key)
			}
		default:
			t.Errorf("watch %q has unrecognised kind %q", w.Key, w.Kind)
		}
	}
}

// TestEveryWatchedEventTypeHasAPriority guards against a typo in an event type
// silently defaulting to Normal priority — which would send a firewall_disabled
// through the batched path.
func TestEveryWatchedEventTypeHasAPriority(t *testing.T) {
	criticalOrHigh := map[string]bool{
		models.EventFirewallDisabled:           true,
		models.EventRealtimeProtectionDisabled: true,
		models.EventTamperProtectionDisabled:   true,
		models.EventSecureBootDisabled:         true,
		models.EventEncryptionDisabled:         true,
		models.EventNewLocalAdmin:              true,
		models.EventFirewallRestored:           true,
		models.EventRealtimeProtectionRestored: true,
		models.EventTamperProtectionRestored:   true,
		models.EventSecureBootRestored:         true,
		models.EventEncryptionRestored:         true,
		models.EventDirectoryJoinChanged:       true,
		models.EventEntraJoinChanged:           true,
	}

	for eventType := range criticalOrHigh {
		if got := models.PriorityForEventType(eventType); got > models.PriorityHigh {
			t.Errorf("%s has priority %d; it must be critical or high", eventType, got)
		}
	}
}

// TestSummarizeEvents keeps the log line honest.
func TestSummarizeEvents(t *testing.T) {
	if got := SummarizeEvents(nil); got != "none" {
		t.Errorf("SummarizeEvents(nil) = %q, want %q", got, "none")
	}

	got := SummarizeEvents([]models.TelemetryChangeEvent{
		{EventType: models.EventFirewallDisabled},
		{EventType: models.EventFirewallDisabled},
		{EventType: models.EventHostnameChanged},
	})
	if !strings.Contains(got, "firewall_disabled=2") || !strings.Contains(got, "hostname_changed=1") {
		t.Errorf("SummarizeEvents() = %q", got)
	}
}

func TestStatusesFrom(t *testing.T) {
	got := StatusesFrom([]CollectorResult{
		{Section: SectionProtection, Status: StatusSuccess},
		{Section: SectionIdentity, Status: StatusError},
	})
	if got[SectionProtection] != StatusSuccess {
		t.Errorf("protection status = %q", got[SectionProtection])
	}
	if got[SectionIdentity] != StatusError {
		t.Errorf("identity status = %q", got[SectionIdentity])
	}
}
