package telemetry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeCollector struct {
	name     string
	section  string
	capKey   string
	capState CapabilityState
	payload  any
	status   Status
	calls    int
}

func (f *fakeCollector) Name() string       { return f.name }
func (f *fakeCollector) Section() string    { return f.section }
func (f *fakeCollector) SchemaVersion() int { return 1 }

func (f *fakeCollector) Capability(context.Context, CollectorConfig) (string, CapabilityState) {
	return f.capKey, f.capState
}

func (f *fakeCollector) Collect(context.Context, CollectorConfig) (any, CollectorResult) {
	f.calls++
	status := f.status
	if status == "" {
		status = StatusSuccess
	}
	return f.payload, CollectorResult{
		Collector:   f.name,
		Section:     f.section,
		Status:      status,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		// Deliberately volatile: a different duration on every call, to prove it
		// cannot influence section fingerprints.
		DurationMS: int64(f.calls) * 137,
	}
}

type fakeState struct {
	states     map[string]*SectionState
	generation uint64
}

func (f *fakeState) NextCollectionGeneration() (uint64, error) {
	f.generation++
	return f.generation, nil
}

func newFakeState() *fakeState { return &fakeState{states: make(map[string]*SectionState)} }

func (f *fakeState) GetAll() (map[string]*SectionState, error) {
	out := make(map[string]*SectionState, len(f.states))
	for k, v := range f.states {
		cp := *v
		out[k] = &cp
	}
	return out, nil
}

func (f *fakeState) MarkCollected(section string, schemaVersion int, hash string, itemCount int, status string, at time.Time) error {
	st, ok := f.states[section]
	if !ok {
		st = &SectionState{Section: section}
		f.states[section] = st
	}
	st.SchemaVersion = schemaVersion
	st.Hash = hash
	st.ItemCount = itemCount
	st.Status = status
	st.LastCollectedAt = at
	return nil
}

func (f *fakeState) MarkUploaded(section string, at time.Time) error {
	st, ok := f.states[section]
	if !ok {
		return nil
	}
	st.LastUploadedAt = at
	st.LastReconciledAt = at
	return nil
}

type fakeQueue struct {
	messages []QueuedMessage
}

func (f *fakeQueue) Enqueue(msg QueuedMessage) (int64, error) {
	f.messages = append(f.messages, msg)
	return 0, nil
}

func (f *fakeQueue) Depth() (int, error) { return len(f.messages), nil }

// ── tests ────────────────────────────────────────────────────────────────────

func newTestService(t *testing.T, collectors ...Collector) (*Service, *fakeState, *fakeQueue) {
	t.Helper()
	set := NewCollectorSet()
	for _, c := range collectors {
		if err := set.Register(c); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	state := newFakeState()
	queue := &fakeQueue{}
	return NewService(NewDefaultRegistry(), set, state, queue), state, queue
}

// TestRunCycleUploadsOnceThenSuppresses is the behavioural proof of the whole
// design: the first cycle uploads, and an identical second cycle sends nothing
// even though the collector reported a different duration.
func TestRunCycleUploadsOnceThenSuppresses(t *testing.T) {
	c := &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1", "serial": "SN-1"},
	}
	svc, _, queue := newTestService(t, c)

	now := baseTime
	svc.SetClock(func() time.Time { return now })
	cfg := &config.Config{DeviceID: "dev-1", CurrentVersion: "v1.0.0"}

	// Cycle 1: first upload.
	report, err := svc.RunCycle(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if len(report.UploadedSections) != 1 {
		t.Fatalf("cycle 1 uploaded %v, want [identity]", report.UploadedSections)
	}
	if report.Reasons[SectionIdentity] != ReasonFirstUpload {
		t.Errorf("cycle 1 reason = %q, want %q", report.Reasons[SectionIdentity], ReasonFirstUpload)
	}

	// Delivery is what advances the reconcile clock.
	svc.MarkDelivered([]string{SectionIdentity}, now)

	// Cycle 2, one minute later, identical system state.
	now = baseTime.Add(time.Minute)
	report, err = svc.RunCycle(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(report.UploadedSections) != 0 {
		t.Fatalf("cycle 2 uploaded %v, want nothing", report.UploadedSections)
	}
	if report.Reasons[SectionIdentity] != ReasonUnchanged {
		t.Errorf("cycle 2 reason = %q, want %q", report.Reasons[SectionIdentity], ReasonUnchanged)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queue holds %d messages after two cycles, want 1", len(queue.messages))
	}
}

// TestRunCycleHealthUsesSectionNotCapabilityKey is a regression test. A
// section's name and the capability key that gates it are not always the same
// string — SectionPatches is "patches" but its key is CapKeyPatchInventory
// ("patch_inventory"), and this fixture's own SectionIdentity/CapKeyDirectoryJoin
// pairing is deliberately mismatched the same way. Health must key off the
// section, not assume it equals the capability key, or a perfectly healthy
// collector is misreported as not_applicable purely because the two strings
// differ.
func TestRunCycleHealthUsesSectionNotCapabilityKey(t *testing.T) {
	c := &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1"},
	}
	svc, _, _ := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}

	if len(report.Health.Domains) != 1 {
		t.Fatalf("expected one domain, got %+v", report.Health.Domains)
	}
	if got := report.Health.Domains[0].State; got != HealthHealthy {
		t.Errorf("domain state = %q, want %q", got, HealthHealthy)
	}
}

// TestRunCycleReconcilesWhenDue verifies unchanged data still resyncs once its
// section's interval elapses.
func TestRunCycleReconcilesWhenDue(t *testing.T) {
	c := &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1"},
	}
	svc, _, queue := newTestService(t, c)

	now := baseTime
	svc.SetClock(func() time.Time { return now })
	cfg := &config.Config{DeviceID: "dev-1"}

	if _, err := svc.RunCycle(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	svc.MarkDelivered([]string{SectionIdentity}, now)

	// 23h later: still suppressed (identity reconciles at 24h).
	now = baseTime.Add(23 * time.Hour)
	report, _ := svc.RunCycle(context.Background(), cfg)
	if len(report.UploadedSections) != 0 {
		t.Fatalf("uploaded at 23h: %v, want nothing", report.UploadedSections)
	}

	// 24h later: due.
	now = baseTime.Add(24 * time.Hour)
	report, _ = svc.RunCycle(context.Background(), cfg)
	if len(report.UploadedSections) != 1 {
		t.Fatalf("uploaded at 24h: %v, want [identity]", report.UploadedSections)
	}
	if report.Reasons[SectionIdentity] != ReasonReconcileDue {
		t.Errorf("reason = %q, want %q", report.Reasons[SectionIdentity], ReasonReconcileDue)
	}
	if len(queue.messages) != 2 {
		t.Fatalf("queue holds %d messages, want 2", len(queue.messages))
	}
}

// TestRunCycleSkipsUnsupportedCapability verifies a collector whose capability
// says there is nothing to collect is not run, yet still reports why.
func TestRunCycleSkipsUnsupportedCapability(t *testing.T) {
	c := &fakeCollector{
		name: "battery", section: SectionHealth,
		capKey: CapKeyBatteryDetail, capState: CapNotPresent,
		payload: map[string]any{"should": "not appear"},
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}

	if c.calls != 0 {
		t.Errorf("collector ran %d times despite not_present capability", c.calls)
	}
	if len(queue.messages) != 0 {
		t.Errorf("queued %d messages for an absent capability", len(queue.messages))
	}
	if got := report.Capabilities.Get(CapKeyBatteryDetail); got != CapNotPresent {
		t.Errorf("capability = %q, want %q", got, CapNotPresent)
	}
	if len(report.Results) != 1 || report.Results[0].Status != StatusUnsupported {
		t.Fatalf("expected one unsupported result, got %+v", report.Results)
	}
}

// TestEnvelopeCarriesSectionsAndMeta checks the wire shape the backend contract
// depends on, in particular that Sections is present (so a partial payload is
// merged, not treated as the whole truth) and that Meta sits outside the data.
func TestEnvelopeCarriesSectionsAndMeta(t *testing.T) {
	c := &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1"},
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	if _, err := svc.RunCycle(context.Background(),
		&config.Config{DeviceID: "dev-42", CurrentVersion: "v9.9.9"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("expected one queued message, got %d", len(queue.messages))
	}

	var wire struct {
		Payload struct {
			SchemaVersion   int            `json:"schema_version"`
			DeviceID        string         `json:"device_id"`
			AgentVersion    string         `json:"agent_version"`
			Platform        string         `json:"platform"`
			Class           string         `json:"class"`
			Sections        []string       `json:"sections"`
			SectionVersions map[string]int `json:"section_versions"`
			Data            map[string]any `json:"data"`
			Meta            map[string]any `json:"meta"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(queue.messages[0].Payload, &wire); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	p := wire.Payload
	if p.SchemaVersion != EnvelopeSchemaVersion {
		t.Errorf("schema_version = %d, want %d", p.SchemaVersion, EnvelopeSchemaVersion)
	}
	if p.DeviceID != "dev-42" || p.AgentVersion != "v9.9.9" {
		t.Errorf("identity fields wrong: device=%q agent=%q", p.DeviceID, p.AgentVersion)
	}
	if p.Platform == "" {
		t.Error("platform must be set")
	}
	if len(p.Sections) != 1 || p.Sections[0] != SectionIdentity {
		t.Errorf("sections = %v, want [%s]", p.Sections, SectionIdentity)
	}
	if p.SectionVersions[SectionIdentity] != 1 {
		t.Errorf("section version = %d, want 1", p.SectionVersions[SectionIdentity])
	}
	if _, ok := p.Data[SectionIdentity]; !ok {
		t.Errorf("data missing section %q", SectionIdentity)
	}

	// Meta must be outside the section data — the structural rule that keeps
	// volatile diagnostics from poisoning change detection.
	if p.Meta == nil {
		t.Fatal("meta block missing")
	}
	for _, key := range []string{"results", "telemetry_health"} {
		if _, ok := p.Meta[key]; !ok {
			t.Errorf("meta missing %q", key)
		}
		if _, leaked := p.Data[key]; leaked {
			t.Errorf("%q leaked into section data", key)
		}
	}
}

// TestRunCycleFailsLoudlyOnMetaInSection verifies a collector that returns
// envelope metadata as its payload aborts the cycle instead of silently
// disabling reconciliation for that section.
func TestRunCycleFailsLoudlyOnMetaInSection(t *testing.T) {
	c := &fakeCollector{
		name: "broken", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: &TelemetryHealth{PendingQueueDepth: 5},
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	_, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err == nil {
		t.Fatal("expected an error when a collector returns envelope metadata as its payload")
	}
	if len(queue.messages) != 0 {
		t.Fatalf("nothing should be queued after a fingerprint failure, got %d", len(queue.messages))
	}
}

// TestUnregisteredSectionIsSkipped verifies a collector filling a section with
// no reconcile policy is skipped rather than uploaded on an unknown cadence.
func TestUnregisteredSectionIsSkipped(t *testing.T) {
	c := &fakeCollector{
		name: "mystery", section: "not_a_registered_section",
		capKey: CapKeyTPM, capState: CapSupported,
		payload: map[string]any{"x": 1},
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(report.CollectedSections) != 0 || len(queue.messages) != 0 {
		t.Fatalf("unregistered section was processed: collected=%v queued=%d",
			report.CollectedSections, len(queue.messages))
	}
}

// TestCollectorConfigFromRespectsPrivacyDefaults verifies command-line capture
// is off unless explicitly enabled.
func TestCollectorConfigFromRespectsPrivacyDefaults(t *testing.T) {
	if got := CollectorConfigFrom(&config.Config{}); got.CollectProcessCmdline {
		t.Error("process command-line capture must default to off")
	}
	if got := CollectorConfigFrom(nil); got.CollectProcessCmdline {
		t.Error("nil config must not enable command-line capture")
	}
	cfg := &config.Config{ProcessesCollectCmdline: true}
	if got := CollectorConfigFrom(cfg); !got.CollectProcessCmdline {
		t.Error("explicit opt-in was not honoured")
	}
}

// TestEmptyCollectorSetProducesNoTraffic covers the Phase B state: the layer is
// wired but no collectors are registered yet, which must be silent rather than
// producing empty envelopes.
func TestEmptyCollectorSetProducesNoTraffic(t *testing.T) {
	svc, _, queue := newTestService(t)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(queue.messages) != 0 {
		t.Fatalf("queued %d messages with no collectors registered", len(queue.messages))
	}
	if report.Health == nil {
		t.Error("health report should still be produced")
	}
}
