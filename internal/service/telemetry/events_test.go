package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
	tel "sentinelgo/internal/telemetry"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// recordedRequest is one call the fake backend received.
type recordedRequest struct {
	Path string
	Body []byte
}

// recorder is a fake backend that accepts everything and remembers what it was
// sent, so a test can assert which RPC a message was routed to.
type recorder struct {
	mu       sync.Mutex
	requests []recordedRequest
	status   int
}

func newRecorder() *recorder { return &recorder{status: http.StatusOK} }

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		r.requests = append(r.requests, recordedRequest{Path: req.URL.Path, Body: body})
		status := r.status
		r.mu.Unlock()

		w.WriteHeader(status)
		if status < 400 {
			_, _ = w.Write([]byte(`{"msg_id":1,"queue":"telemetry"}`))
		}
	}
}

func (r *recorder) setStatus(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = code
}

func (r *recorder) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.requests))
	for i, req := range r.requests {
		out[i] = req.Path
	}
	return out
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// eventTestEnv holds a service wired for change detection over real SQLite
// stores in a temp directory that persists across a simulated restart.
type eventTestEnv struct {
	t   *testing.T
	dir string
	cfg *config.Config
	rec *recorder
	srv *httptest.Server
}

func newEventTestEnv(t *testing.T) *eventTestEnv {
	t.Helper()

	rec := newRecorder()
	srv := httptest.NewServer(rec.handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	return &eventTestEnv{
		t:   t,
		dir: dir,
		rec: rec,
		srv: srv,
		cfg: &config.Config{
			Path:                   filepath.Join(dir, "config.json"),
			DeviceID:               "dev-events",
			SupabaseURL:            srv.URL,
			SupabaseKey:            "anon-key",
			AccessToken:            "jwt-token",
			TelemetryEnabled:       true,
			TelemetryEventsEnabled: true,
			TelemetryEventCooldown: config.Duration(time.Nanosecond),
		},
	}
}

// open builds a service against the same on-disk databases. Calling it twice is
// how these tests simulate an agent restart.
func (e *eventTestEnv) open() *Service {
	e.t.Helper()
	svc, err := New(e.cfg, tel.NewCollectorSet())
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	e.t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// runCycle drives the domain engine directly with supplied section data, which
// is what a real cycle hands it after collection.
func (e *eventTestEnv) runCycle(svc *Service, at time.Time, data tel.SectionData) []models.TelemetryChangeEvent {
	e.t.Helper()

	engine := svc.Domain().EventEngine()
	if engine == nil {
		e.t.Fatal("change detection is not enabled on this service")
	}
	engine.SetClock(func() time.Time { return at })

	statuses := make(map[string]tel.Status, len(data))
	for section := range data {
		statuses[section] = tel.StatusSuccess
	}

	result, err := engine.Process(e.cfg.DeviceID, "v3.2.9", data, statuses)
	if err != nil {
		e.t.Fatalf("Process: %v", err)
	}
	return result.Events
}

func protectionSection(state string) tel.SectionData {
	return tel.SectionData{tel.SectionProtection: map[string]any{
		"firewall":            map[string]any{"state": state},
		"realtime_protection": map[string]any{"state": "enabled"},
		"tamper_protection":   map[string]any{"state": "enabled"},
	}}
}

// enqueueEvent puts one event message on the queue the way the cycle would.
func enqueueEvent(t *testing.T, svc *Service, priority int) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"payload": tel.EventEnvelope{
		SchemaVersion: tel.EventSchemaVersion,
		DeviceID:      "dev-events",
		Platform:      "windows",
		Events: []models.TelemetryChangeEvent{{
			EventID:   "evt-1",
			EventType: models.EventFirewallDisabled,
			Section:   tel.SectionProtection,
			Priority:  models.EventPriority(priority),
		}},
	}})
	if err != nil {
		t.Fatalf("marshal event envelope: %v", err)
	}

	if _, err := svc.queueStore.Enqueue(store.OutboundMessage{
		SnapshotID: "snap-events",
		Section:    "", // events carry no sections, by design
		Class:      string(tel.ClassEvent),
		Priority:   priority,
		BatchCount: 1,
		Payload:    string(body),
	}); err != nil {
		t.Fatalf("enqueue event: %v", err)
	}
}

// shortContext bounds a flush that is expected to fail transiently, so the
// exponential backoff in the shared enqueue retry policy does not add a minute
// to the test run.
func shortContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

// ── 17. event-class routing over real HTTP ───────────────────────────────────

// TestEventsRouteToTheEventsRPC is the wiring proof: a queued message's class
// is the only thing that decides which backend endpoint it reaches.
func TestEventsRouteToTheEventsRPC(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	enqueueTestMessage(t, svc, tel.SectionIdentity, `{"payload":{"sections":["identity"]}}`)
	enqueueEvent(t, svc, int(models.PriorityCritical))

	if _, err := svc.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	paths := env.rec.paths()
	if len(paths) != 2 {
		t.Fatalf("backend saw %d request(s), want 2: %v", len(paths), paths)
	}

	var sawSections, sawEvents bool
	for _, p := range paths {
		switch p {
		case rpcEnqueueTelemetry:
			sawSections = true
		case rpcEnqueueTelemetryEvents:
			sawEvents = true
		default:
			t.Errorf("unexpected RPC path %q", p)
		}
	}
	if !sawSections {
		t.Errorf("section message did not reach %s", rpcEnqueueTelemetry)
	}
	if !sawEvents {
		t.Errorf("event message did not reach %s", rpcEnqueueTelemetryEvents)
	}
}

func TestRPCForClass(t *testing.T) {
	tests := map[string]string{
		string(tel.ClassEvent):     rpcEnqueueTelemetryEvents,
		string(tel.ClassInventory): rpcEnqueueTelemetry,
		string(tel.ClassPosture):   rpcEnqueueTelemetry,
		string(tel.ClassHealth):    rpcEnqueueTelemetry,
		// An unrecognised class must not silently become an event.
		"":         rpcEnqueueTelemetry,
		"nonsense": rpcEnqueueTelemetry,
	}
	for class, want := range tests {
		if got := rpcForClass(class); got != want {
			t.Errorf("rpcForClass(%q) = %q, want %q", class, got, want)
		}
	}
}

// ── 19. event delivery must not advance section state ────────────────────────

// TestEventDeliveryDoesNotAdvanceSectionState is the reconciliation guarantee.
//
// If delivering an event advanced its source section's reconcile clock, the
// backend would be told the section was up to date while never having received
// it, and the section's real payload would sit unsent until its next content
// change — silent data loss with no error anywhere.
func TestEventDeliveryDoesNotAdvanceSectionState(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	seedSectionState(t, svc, tel.SectionProtection)

	before, err := svc.stateStore.Get(tel.SectionProtection)
	if err != nil {
		t.Fatalf("Get section state: %v", err)
	}
	if !before.LastReconciledAt.IsZero() {
		t.Fatalf("section was already reconciled before the test: %v", before.LastReconciledAt)
	}

	enqueueEvent(t, svc, int(models.PriorityCritical))

	result, err := svc.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if result.Delivered != 1 {
		t.Fatalf("delivered %d message(s), want 1", result.Delivered)
	}

	after, err := svc.stateStore.Get(tel.SectionProtection)
	if err != nil {
		t.Fatalf("Get section state: %v", err)
	}
	if !after.LastReconciledAt.IsZero() {
		t.Errorf("event delivery advanced the section reconcile clock to %v", after.LastReconciledAt)
	}
	if !after.LastUploadedAt.IsZero() {
		t.Errorf("event delivery marked the section uploaded at %v", after.LastUploadedAt)
	}
	if len(result.Sections) != 0 {
		t.Errorf("flush reported sections %v for an event-only drain", result.Sections)
	}
}

// TestEventDeliveryWithASectionNameStillDoesNotAdvance covers the defence in
// depth: even a malformed event row that DOES name a section must not advance
// reconciliation, because the class check runs regardless of the section list.
func TestEventDeliveryWithASectionNameStillDoesNotAdvance(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	seedSectionState(t, svc, tel.SectionProtection)

	if _, err := svc.queueStore.Enqueue(store.OutboundMessage{
		SnapshotID: "snap-bad",
		Section:    tel.SectionProtection, // wrong, but must be harmless
		Class:      string(tel.ClassEvent),
		Priority:   int(models.PriorityCritical),
		BatchCount: 1,
		Payload:    `{"payload":{"events":[]}}`,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if _, err := svc.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	after, err := svc.stateStore.Get(tel.SectionProtection)
	if err != nil {
		t.Fatalf("Get section state: %v", err)
	}
	if !after.LastReconciledAt.IsZero() {
		t.Fatal("a mislabelled event message advanced section reconciliation")
	}
}

// ── 20 & 21. offline durability ──────────────────────────────────────────────

// TestQueuedEventSurvivesAnOfflineBackend: the whole point of the durable queue
// is that being unreachable costs nothing but time.
func TestQueuedEventSurvivesAnOfflineBackend(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	env.rec.setStatus(http.StatusServiceUnavailable)
	enqueueEvent(t, svc, int(models.PriorityCritical))

	// A 5xx is transient: the drain stops and the row stays put. The shared
	// enqueue retry policy backs off exponentially, so the context is bounded
	// here to cut the wait short — the assertion is about durability, not about
	// how long the agent is willing to keep trying.
	_, _ = svc.Flush(shortContext(t))

	depth, err := svc.QueueDepth()
	if err != nil {
		t.Fatalf("QueueDepth: %v", err)
	}
	if depth != 1 {
		t.Fatalf("queue depth = %d after an offline flush, want 1", depth)
	}

	// Backend comes back.
	env.rec.setStatus(http.StatusOK)
	result, err := svc.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}
	if result.Delivered != 1 {
		t.Fatalf("delivered %d after recovery, want 1", result.Delivered)
	}
}

// TestQueuedEventSurvivesRestart reopens the service against the same database
// files, which is exactly what restarting the agent does.
func TestQueuedEventSurvivesRestart(t *testing.T) {
	env := newEventTestEnv(t)

	first := env.open()
	env.rec.setStatus(http.StatusServiceUnavailable)
	enqueueEvent(t, first, int(models.PriorityCritical))
	_, _ = first.Flush(shortContext(t))
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// "Restart".
	second := env.open()

	depth, err := second.QueueDepth()
	if err != nil {
		t.Fatalf("QueueDepth: %v", err)
	}
	if depth != 1 {
		t.Fatalf("queue depth after restart = %d, want 1", depth)
	}

	env.rec.setStatus(http.StatusOK)
	result, err := second.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if result.Delivered != 1 {
		t.Fatalf("delivered %d after restart, want 1", result.Delivered)
	}
	if got := env.rec.paths()[len(env.rec.paths())-1]; got != rpcEnqueueTelemetryEvents {
		t.Errorf("restarted delivery routed to %q; the class must be read from the stored row", got)
	}
}

// ── 22. priority ordering on the real queue ──────────────────────────────────

// TestCriticalEventsAreOfferedFirst: the queue orders by priority, so a
// critical event queued after a backlog of routine telemetry still goes out
// ahead of it.
func TestCriticalEventsAreOfferedFirst(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	// A backlog of routine inventory first...
	for i := 0; i < 5; i++ {
		enqueueTestMessage(t, svc, tel.SectionIdentity, `{"payload":{"sections":["identity"]}}`)
	}
	// ...then the critical event.
	enqueueEvent(t, svc, int(models.PriorityCritical))

	pending, err := svc.Pending(10)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 6 {
		t.Fatalf("pending = %d, want 6", len(pending))
	}
	if pending[0].Class != string(tel.ClassEvent) {
		t.Errorf("head of queue is class %q, want %q; the critical event must overtake the backlog",
			pending[0].Class, tel.ClassEvent)
	}
	if pending[0].Priority != int(models.PriorityCritical) {
		t.Errorf("head priority = %d, want %d", pending[0].Priority, models.PriorityCritical)
	}
}

// ── 15. watched state persistence through the real store ─────────────────────

// TestWatchedStateSurvivesRestartOnDisk exercises the SQLite path, migration
// included: a baseline written by one process must be read back by the next,
// or every restart would re-seed and swallow the first change after it.
func TestWatchedStateSurvivesRestartOnDisk(t *testing.T) {
	env := newEventTestEnv(t)
	base := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)

	first := env.open()
	if events := env.runCycle(first, base, protectionSection("enabled")); len(events) != 0 {
		t.Fatalf("the seeding cycle emitted %d event(s)", len(events))
	}

	depth, err := first.WatchedStateDepth()
	if err != nil {
		t.Fatalf("WatchedStateDepth: %v", err)
	}
	if depth == 0 {
		t.Fatal("nothing was persisted to telemetry_watched_state")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// "Restart", then the firewall goes down.
	second := env.open()
	events := env.runCycle(second, base.Add(15*time.Minute), protectionSection("disabled"))

	if len(events) != 1 {
		t.Fatalf("after restart the change produced %d event(s), want 1", len(events))
	}
	if events[0].EventType != models.EventFirewallDisabled {
		t.Errorf("event type = %q, want %q", events[0].EventType, models.EventFirewallDisabled)
	}
	if events[0].Priority != models.PriorityCritical {
		t.Errorf("priority = %d, want critical", events[0].Priority)
	}
}

// TestWatchedStateIsSeparateFromSectionReset: resetting reconciliation must not
// erase the change-detection baseline. Re-sending inventory the backend already
// has is harmless; forgetting what the device looked like means changes during
// the gap go unreported.
func TestWatchedStateIsSeparateFromSectionReset(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()
	base := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)

	env.runCycle(svc, base, protectionSection("enabled"))

	before, err := svc.WatchedStateDepth()
	if err != nil {
		t.Fatalf("WatchedStateDepth: %v", err)
	}

	if err := svc.ResetState(); err != nil {
		t.Fatalf("ResetState: %v", err)
	}

	after, err := svc.WatchedStateDepth()
	if err != nil {
		t.Fatalf("WatchedStateDepth: %v", err)
	}
	if after != before {
		t.Fatalf("ResetState changed watched-state depth from %d to %d", before, after)
	}

	// And the baseline still works: the next change is still reported.
	events := env.runCycle(svc, base.Add(15*time.Minute), protectionSection("disabled"))
	if len(events) != 1 {
		t.Fatalf("after ResetState the change produced %d event(s), want 1", len(events))
	}
}

// ── 23. feature gate ─────────────────────────────────────────────────────────

// TestChangeDetectionIsOffByDefault: a config that has never heard of Phase G
// must behave exactly as it did before.
func TestChangeDetectionIsOffByDefault(t *testing.T) {
	env := newEventTestEnv(t)
	env.cfg.TelemetryEventsEnabled = false

	svc := env.open()
	if svc.EventsEnabled() {
		t.Fatal("change detection is on with telemetry_events_enabled=false")
	}
	if svc.Domain().EventEngine() != nil {
		t.Fatal("an event engine was attached while disabled")
	}

	depth, err := svc.WatchedStateDepth()
	if err != nil {
		t.Fatalf("WatchedStateDepth: %v", err)
	}
	if depth != 0 {
		t.Errorf("watched state holds %d row(s) while disabled", depth)
	}
}

// TestInvalidEventConfigFailsLoudly: change detection drives security alerting,
// so a configuration that would silently suppress events must stop startup
// rather than be quietly corrected.
func TestInvalidEventConfigFailsLoudly(t *testing.T) {
	env := newEventTestEnv(t)
	// A cooldown longer than the flapping window means the flap counter always
	// resets before it can reach the threshold.
	env.cfg.TelemetryEventCooldown = config.Duration(2 * time.Hour)
	env.cfg.TelemetryEventFlapWindow = config.Duration(time.Hour)

	svc, err := New(env.cfg, tel.NewCollectorSet())
	if err == nil {
		_ = svc.Close()
		t.Fatal("New() accepted a configuration that cannot detect flapping")
	}
}

// TestEventConfigDefaultsAreApplied covers the accessors an existing config
// file relies on: every unset field must resolve to a vetted value rather than
// to zero.
func TestEventConfigDefaultsAreApplied(t *testing.T) {
	cfg := &config.Config{}

	if got := cfg.GetTelemetryEventCooldown(); got != 10*time.Minute {
		t.Errorf("cooldown default = %v, want 10m", got)
	}
	if got := cfg.GetTelemetryEventFlapWindow(); got != time.Hour {
		t.Errorf("flap window default = %v, want 1h", got)
	}
	if got := cfg.GetTelemetryEventFlapThreshold(); got != 4 {
		t.Errorf("flap threshold default = %d, want 4", got)
	}
	// Zero debounce is meaningful (confirm on the next cycle), not unset.
	if got := cfg.GetTelemetryEventDebounce(); got != 0 {
		t.Errorf("debounce default = %v, want 0", got)
	}
	// A threshold of 1 would classify every first change as flapping.
	cfg.TelemetryEventFlapThreshold = 1
	if got := cfg.GetTelemetryEventFlapThreshold(); got != 4 {
		t.Errorf("threshold of 1 was honoured (%d); it must fall back to the default", got)
	}
}

// ── round trip of the wire payload ───────────────────────────────────────────

// TestDeliveredEventPayloadMatchesTheContract inspects the bytes the backend
// actually receives.
func TestDeliveredEventPayloadMatchesTheContract(t *testing.T) {
	env := newEventTestEnv(t)
	svc := env.open()

	enqueueEvent(t, svc, int(models.PriorityCritical))
	if _, err := svc.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if env.rec.count() != 1 {
		t.Fatalf("backend saw %d request(s), want 1", env.rec.count())
	}

	var wrapper struct {
		Payload struct {
			SchemaVersion int                           `json:"schema_version"`
			DeviceID      string                        `json:"device_id"`
			Platform      string                        `json:"platform"`
			Events        []models.TelemetryChangeEvent `json:"events"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(env.rec.requests[0].Body, &wrapper); err != nil {
		t.Fatalf("delivered body is not the contracted shape: %v", err)
	}

	got := wrapper.Payload
	if got.DeviceID != "dev-events" {
		t.Errorf("device_id = %q", got.DeviceID)
	}
	if got.SchemaVersion != tel.EventSchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, tel.EventSchemaVersion)
	}
	if len(got.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(got.Events))
	}
	if got.Events[0].EventID == "" {
		t.Error("event_id is empty; delivery would not be idempotent")
	}
	if got.Events[0].EventType != models.EventFirewallDisabled {
		t.Errorf("event_type = %q", got.Events[0].EventType)
	}
}
