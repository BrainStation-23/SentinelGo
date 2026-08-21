package telemetry

import (
	"encoding/json"
	"testing"
	"time"

	"sentinelgo/internal/models"
)

// ── fakes and helpers ────────────────────────────────────────────────────────

// memWatchedStore is an in-memory WatchedStateStore.
//
// It deep-copies on both read and write, so a test cannot accidentally pass
// because the engine mutated a pointer the store still holds — the SQLite store
// obviously cannot share memory that way, and a fake that does would hide
// exactly the restart bugs these tests exist to catch.
type memWatchedStore struct {
	rows   map[string]WatchedState
	putErr error
	getErr error
}

func newMemWatchedStore() *memWatchedStore {
	return &memWatchedStore{rows: make(map[string]WatchedState)}
}

func (m *memWatchedStore) GetAll() (map[string]*WatchedState, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	out := make(map[string]*WatchedState, len(m.rows))
	for k, v := range m.rows {
		cp := v
		cp.Value = cloneValue(v.Value)
		cp.Pending = cloneValue(v.Pending)
		out[k] = &cp
	}
	return out, nil
}

func (m *memWatchedStore) Put(state *WatchedState) error {
	if m.putErr != nil {
		return m.putErr
	}
	cp := *state
	cp.Value = cloneValue(state.Value)
	cp.Pending = cloneValue(state.Pending)
	m.rows[state.Key] = cp
	return nil
}

func (m *memWatchedStore) Delete(key string) error {
	delete(m.rows, key)
	return nil
}

func cloneValue(v Value) Value {
	out := v
	if v.Members != nil {
		out.Members = append([]string(nil), v.Members...)
	}
	return out
}

// clock is a manually advanced time source.
type clock struct{ t time.Time }

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)}
}
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

const testDeviceID = "a1b2c3d4e5f6a7b8"

// harness drives the engine over a sequence of cycles.
type harness struct {
	t      *testing.T
	engine *EventEngine
	store  *memWatchedStore
	clk    *clock
}

func newHarness(t *testing.T, cfg EventConfig, watches ...Watch) *harness {
	t.Helper()
	if len(watches) == 0 {
		watches = DefaultWatches()
	}
	store := newMemWatchedStore()
	clk := newClock()
	engine := NewEventEngine(watches, store, cfg)
	engine.SetClock(clk.now)
	return &harness{t: t, engine: engine, store: store, clk: clk}
}

// cycle runs one collection cycle where every supplied section succeeded.
func (h *harness) cycle(data SectionData) *EventResult {
	h.t.Helper()
	statuses := make(map[string]Status, len(data))
	for section := range data {
		statuses[section] = StatusSuccess
	}
	return h.cycleWithStatuses(data, statuses)
}

func (h *harness) cycleWithStatuses(data SectionData, statuses map[string]Status) *EventResult {
	h.t.Helper()
	// Every real cycle advances the clock; without this, the "one successful
	// cycle" debounce rule could never be satisfied in a test.
	h.clk.advance(15 * time.Minute)

	result, err := h.engine.Process(testDeviceID, "v3.2.9", data, statuses)
	if err != nil {
		h.t.Fatalf("Process() error = %v", err)
	}
	return result
}

// eventTypes lists the event types a result produced, for concise assertions.
func eventTypes(result *EventResult) []string {
	out := make([]string, 0, len(result.Events))
	for _, e := range result.Events {
		out = append(out, e.EventType)
	}
	return out
}

func hasEvent(result *EventResult, eventType string) bool {
	for _, e := range result.Events {
		if e.EventType == eventType {
			return true
		}
	}
	return false
}

// Section payload builders, matching the real collectors' JSON shapes.

// protectionPayload is the "security_protection" section payload alone.
func protectionPayload(firewall, realtime, tamper string) any {
	return map[string]any{
		"firewall":            map[string]any{"state": firewall},
		"realtime_protection": map[string]any{"state": realtime},
		"tamper_protection":   map[string]any{"state": tamper},
	}
}

// protectionData wraps it as a one-section cycle, the common case.
func protectionData(firewall, realtime, tamper string) SectionData {
	return SectionData{SectionProtection: protectionPayload(firewall, realtime, tamper)}
}

func encryptionData(volumes map[string]string) any {
	list := make([]any, 0, len(volumes))
	for mount, status := range volumes {
		list = append(list, map[string]any{
			"mount_point":       mount,
			"protection_status": status,
		})
	}
	return map[string]any{"volumes": list}
}

func postureData(accounts ...string) any {
	list := make([]any, 0, len(accounts))
	for _, a := range accounts {
		list = append(list, a)
	}
	return map[string]any{"privileged_accounts": list}
}

func networkData(addrs ...string) any {
	list := make([]any, 0, len(addrs))
	for _, a := range addrs {
		list = append(list, a)
	}
	return map[string]any{"interfaces": []any{
		map[string]any{"name": "eth0", "ipv4_addresses": list},
	}}
}

// ── 1. baseline seeding ──────────────────────────────────────────────────────

// TestFirstObservationSeedsBaselineAndEmitsNothing is the most important
// behaviour in the feature.
//
// Without it, enabling change detection across a fleet would fire a
// firewall_disabled for every device that already had it off, plus a
// new_local_admin for every existing administrator account, in the first cycle
// after deployment — a synthetic incident on day one that would bury any real
// finding underneath it.
func TestFirstObservationSeedsBaselineAndEmitsNothing(t *testing.T) {
	h := newHarness(t, EventConfig{})

	// A device that is ALREADY in the worst possible state: everything off,
	// two admins, no encryption. Not one event may come out of this.
	result := h.cycle(SectionData{
		SectionProtection:   protectionPayload("disabled", "disabled", "disabled"),
		SectionSecureBoot:   map[string]any{"state": "disabled"},
		SectionEncryption:   encryptionData(map[string]string{"C:": "off"}),
		SectionSecurityPost: postureData("Administrator", "eve"),
		SectionIdentity:     map[string]any{"hostname": "host-1"},
	})

	if len(result.Events) != 0 {
		t.Fatalf("first observation produced %d event(s): %v", len(result.Events), eventTypes(result))
	}
	if len(result.Seeded) == 0 {
		t.Fatal("first observation seeded nothing")
	}

	// The baseline must be on disk, or the next cycle would seed again and the
	// first real change would be swallowed forever.
	if len(h.store.rows) == 0 {
		t.Fatal("no watched state was persisted")
	}
	if _, ok := h.store.rows[WatchFirewallState]; !ok {
		t.Errorf("firewall baseline was not stored; keys: %v", storedKeys(h.store))
	}
}

func storedKeys(s *memWatchedStore) []string {
	out := make([]string, 0, len(s.rows))
	for k := range s.rows {
		out = append(out, k)
	}
	return out
}

// ── 2. unchanged values ──────────────────────────────────────────────────────

func TestUnchangedValuesProduceNoEvents(t *testing.T) {
	h := newHarness(t, EventConfig{})
	data := SectionData{
		SectionProtection:   protectionPayload("enabled", "enabled", "enabled"),
		SectionSecurityPost: postureData("Administrator"),
		SectionIdentity:     map[string]any{"hostname": "host-1"},
	}

	h.cycle(data) // seed

	for i := 0; i < 5; i++ {
		result := h.cycle(data)
		if len(result.Events) != 0 {
			t.Fatalf("cycle %d produced events from unchanged data: %v", i+2, eventTypes(result))
		}
		if len(result.Seeded) != 0 {
			t.Fatalf("cycle %d re-seeded %v; the baseline should already exist", i+2, result.Seeded)
		}
	}
}

// ── 3 & 4. firewall disable and restore ──────────────────────────────────────

func TestFirewallDisabledThenRestored(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(protectionData("enabled", "enabled", "enabled"))

	disabled := h.cycle(protectionData("disabled", "enabled", "enabled"))
	if !hasEvent(disabled, models.EventFirewallDisabled) {
		t.Fatalf("firewall going down produced %v, want %s",
			eventTypes(disabled), models.EventFirewallDisabled)
	}

	evt := disabled.Events[0]
	if evt.Priority != models.PriorityCritical {
		t.Errorf("priority = %d, want %d (critical)", evt.Priority, models.PriorityCritical)
	}
	if evt.Severity != models.SeverityCritical {
		t.Errorf("severity = %q, want %q", evt.Severity, models.SeverityCritical)
	}
	if evt.Section != SectionProtection {
		t.Errorf("section = %q, want %q", evt.Section, SectionProtection)
	}

	restored := h.cycle(protectionData("enabled", "enabled", "enabled"))
	if !hasEvent(restored, models.EventFirewallRestored) {
		t.Fatalf("firewall coming back produced %v, want %s",
			eventTypes(restored), models.EventFirewallRestored)
	}
	if restored.Events[0].Priority != models.PriorityHigh {
		t.Errorf("restore priority = %d, want %d (high)",
			restored.Events[0].Priority, models.PriorityHigh)
	}
}

// TestPartialFirewallIsNotDisabled guards against the noisiest possible false
// positive: a laptop whose active profile changes drops one of three profiles,
// which is a degradation, not an unprotected host.
func TestPartialFirewallIsNotDisabled(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(protectionData("enabled", "enabled", "enabled"))
	result := h.cycle(protectionData("partial", "enabled", "enabled"))

	if hasEvent(result, models.EventFirewallDisabled) {
		t.Fatalf("a partially-enabled firewall raised %s", models.EventFirewallDisabled)
	}
	if len(result.Events) != 0 {
		t.Fatalf("enabled -> partial produced %v, want no events", eventTypes(result))
	}
}

// ── 5. failed collection must never become an event ──────────────────────────

// TestCollectorFailureProducesNoEventAndPreservesBaseline is the mandatory
// safety rule.
//
// A collector that errors, times out or is denied permission does not know the
// current value. If that were compared against the baseline it would read as
// "the firewall vanished" — a critical page generated by a broken query rather
// than by anything happening on the device. Worse, if the failure overwrote the
// stored value, the NEXT successful cycle would compare against the failure and
// fire a second, equally false event.
func TestCollectorFailureProducesNoEventAndPreservesBaseline(t *testing.T) {
	failureStatuses := []Status{
		StatusError,
		StatusTimeout,
		StatusPermissionDenied,
		StatusUnsupported,
		StatusPartial,
	}

	for _, status := range failureStatuses {
		t.Run(string(status), func(t *testing.T) {
			h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
			h.cycle(protectionData("enabled", "enabled", "enabled"))

			before := h.store.rows[WatchFirewallState]

			// The collector "reports" a disabled firewall, but with a failure
			// status. Nothing may come of it.
			result := h.cycleWithStatuses(
				protectionData("disabled", "disabled", "disabled"),
				map[string]Status{SectionProtection: status},
			)

			if len(result.Events) != 0 {
				t.Fatalf("status %s produced events: %v", status, eventTypes(result))
			}

			after := h.store.rows[WatchFirewallState]
			if after.Value.Scalar != before.Value.Scalar {
				t.Fatalf("status %s overwrote the last good value: %q -> %q",
					status, before.Value.Scalar, after.Value.Scalar)
			}

			// And the next SUCCESSFUL cycle showing the original value must
			// also be silent — proof the baseline really survived intact.
			recovered := h.cycle(protectionData("enabled", "enabled", "enabled"))
			if len(recovered.Events) != 0 {
				t.Fatalf("recovery cycle after %s produced %v", status, eventTypes(recovered))
			}
		})
	}
}

// TestUnknownValuesAreNeverEvents covers the other half of the rule: a
// successful collection whose VALUE is "unknown" is still not an observation.
func TestUnknownValuesAreNeverEvents(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
	h.cycle(protectionData("enabled", "enabled", "enabled"))

	for _, unknown := range []string{"unknown", "", "not_present"} {
		result := h.cycle(protectionData(unknown, "enabled", "enabled"))
		if len(result.Events) != 0 {
			t.Errorf("value %q produced %v", unknown, eventTypes(result))
		}
		if got := h.store.rows[WatchFirewallState].Value.Scalar; got != "enabled" {
			t.Fatalf("value %q overwrote the baseline with %q", unknown, got)
		}
	}
}

// TestMissingSectionPreservesBaseline covers a section that did not collect at
// all this cycle — the shape a crashed collector actually takes, since RunAll
// omits a section whose result was not OK.
func TestMissingSectionPreservesBaseline(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
	h.cycle(protectionData("enabled", "enabled", "enabled"))

	result := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})
	if len(result.Events) != 0 {
		t.Fatalf("an absent section produced %v", eventTypes(result))
	}
	if got := h.store.rows[WatchFirewallState].Value.Scalar; got != "enabled" {
		t.Fatalf("baseline became %q after the section went missing", got)
	}
	if !containsString(result.SkippedSections, SectionProtection) {
		t.Errorf("SkippedSections = %v, want it to name %s",
			result.SkippedSections, SectionProtection)
	}
}

// ── 6. encryption ────────────────────────────────────────────────────────────

func TestEncryptionDisabledAndRestored(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "on", "D:": "on"})})

	off := h.cycle(SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "on", "D:": "off"})})
	if !hasEvent(off, models.EventEncryptionDisabled) {
		t.Fatalf("turning off a volume produced %v, want %s",
			eventTypes(off), models.EventEncryptionDisabled)
	}
	if off.Events[0].Priority != models.PriorityCritical {
		t.Errorf("priority = %d, want critical", off.Events[0].Priority)
	}

	on := h.cycle(SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "on", "D:": "on"})})
	if !hasEvent(on, models.EventEncryptionRestored) {
		t.Fatalf("re-enabling a volume produced %v, want %s",
			eventTypes(on), models.EventEncryptionRestored)
	}
}

// TestPerMemberEventsAreIndependent proves the membership decomposition: two
// volumes changing in one cycle produce two distinct events, not one merged
// one, and their ids differ.
func TestPerMemberEventsAreIndependent(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
	h.cycle(SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "on", "D:": "on"})})

	result := h.cycle(SectionData{SectionEncryption: encryptionData(map[string]string{"C:": "off", "D:": "off"})})
	if len(result.Events) != 2 {
		t.Fatalf("two volumes changing produced %d event(s): %v", len(result.Events), eventTypes(result))
	}
	if result.Events[0].EventID == result.Events[1].EventID {
		t.Fatal("two distinct changes share an event id; the backend would drop one as a duplicate")
	}
}

// ── 7. local admin ───────────────────────────────────────────────────────────

func TestNewLocalAdminIsCriticalAndNamesTheAccount(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionSecurityPost: postureData("Administrator")})
	result := h.cycle(SectionData{SectionSecurityPost: postureData("Administrator", "eve")})

	if !hasEvent(result, models.EventNewLocalAdmin) {
		t.Fatalf("adding an admin produced %v, want %s", eventTypes(result), models.EventNewLocalAdmin)
	}

	evt := result.Events[0]
	if evt.Priority != models.PriorityCritical {
		t.Errorf("priority = %d, want critical", evt.Priority)
	}

	current, ok := evt.CurrentValue.(*EventValue)
	if !ok {
		t.Fatalf("CurrentValue type = %T, want *EventValue", evt.CurrentValue)
	}
	if current.Member != "eve" {
		t.Errorf("current member = %q, want %q — the event has to say WHO", current.Member, "eve")
	}
}

// TestRemovingAnAdminIsSilent: losing privilege is not an exposure, and firing
// on it would make every offboarding look like a security event.
func TestRemovingAnAdminIsSilent(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionSecurityPost: postureData("Administrator", "eve")})
	result := h.cycle(SectionData{SectionSecurityPost: postureData("Administrator")})

	if len(result.Events) != 0 {
		t.Fatalf("removing an admin produced %v, want no events", eventTypes(result))
	}
}

// ── 8, 9, 10. hostname, IP, directory join ───────────────────────────────────

func TestHostnameChangeIsDebouncedThenReported(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})

	// Normal priority: the first sighting only records a candidate.
	first := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
	if len(first.Events) != 0 {
		t.Fatalf("an unconfirmed hostname change produced %v", eventTypes(first))
	}

	second := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
	if !hasEvent(second, models.EventHostnameChanged) {
		t.Fatalf("a confirmed hostname change produced %v, want %s",
			eventTypes(second), models.EventHostnameChanged)
	}
	if second.Events[0].Priority != models.PriorityNormal {
		t.Errorf("priority = %d, want normal", second.Events[0].Priority)
	}
}

func TestIPChangeReportsABoundedDelta(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionNetwork: networkData("10.0.0.5")})
	h.cycle(SectionData{SectionNetwork: networkData("10.0.0.9")}) // candidate
	result := h.cycle(SectionData{SectionNetwork: networkData("10.0.0.9")})

	if !hasEvent(result, models.EventIPChanged) {
		t.Fatalf("an IP change produced %v, want %s", eventTypes(result), models.EventIPChanged)
	}

	current := result.Events[0].CurrentValue.(*EventValue)
	if len(current.Added) != 1 || current.Added[0] != "10.0.0.9" {
		t.Errorf("added = %v, want [10.0.0.9]", current.Added)
	}
	if len(current.Removed) != 1 || current.Removed[0] != "10.0.0.5" {
		t.Errorf("removed = %v, want [10.0.0.5]", current.Removed)
	}
}

// TestLoopbackAndLinkLocalAreIgnored: these are identical on every device and
// never carry information about where the device actually is.
func TestLoopbackAndLinkLocalAreIgnored(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionNetwork: networkData("10.0.0.5")})
	h.cycle(SectionData{SectionNetwork: networkData("10.0.0.5", "127.0.0.1", "169.254.3.4")})
	result := h.cycle(SectionData{SectionNetwork: networkData("10.0.0.5", "127.0.0.1", "169.254.3.4")})

	if len(result.Events) != 0 {
		t.Fatalf("loopback/link-local addresses produced %v", eventTypes(result))
	}
}

func TestDirectoryJoinChangeIsHighPriority(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionDirectory: map[string]any{"domain_joined": true, "entra_joined": false}})
	result := h.cycle(SectionData{SectionDirectory: map[string]any{"domain_joined": false, "entra_joined": false}})

	if !hasEvent(result, models.EventDirectoryJoinChanged) {
		t.Fatalf("a domain-join change produced %v, want %s",
			eventTypes(result), models.EventDirectoryJoinChanged)
	}
	// High priority means it is not debounced: one observation is enough.
	if result.Events[0].Priority != models.PriorityHigh {
		t.Errorf("priority = %d, want high", result.Events[0].Priority)
	}
}

// TestAbsentBooleanIsUntrusted: every optional boolean in these payloads is a
// pointer so "could not determine" stays distinct from "no". An omitted field
// must not read as false and unjoin the device.
func TestAbsentBooleanIsUntrusted(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionDirectory: map[string]any{"domain_joined": true}})
	result := h.cycle(SectionData{SectionDirectory: map[string]any{}})

	if len(result.Events) != 0 {
		t.Fatalf("an omitted domain_joined produced %v", eventTypes(result))
	}
	if got := h.store.rows[WatchDomainJoined].Value.Scalar; got != "true" {
		t.Fatalf("baseline became %q; the last good value should survive", got)
	}
}

// ── 11 & 12. debounce and revert-before-confirmation ─────────────────────────

// TestRevertBeforeConfirmationProducesZeroEvents is the debounce rule's whole
// purpose: a value that moves and moves back within one cycle never happened as
// far as the backend is concerned.
func TestRevertBeforeConfirmationProducesZeroEvents(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})
	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}}) // candidate
	back := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})

	if len(back.Events) != 0 {
		t.Fatalf("a reverted change produced %v, want nothing", eventTypes(back))
	}
	if state := h.store.rows[WatchHostname]; state.HasPending() {
		t.Error("the candidate value was not cleared on revert")
	}

	// And the value must still be the original, so a later genuine change is
	// still detected.
	if got := h.store.rows[WatchHostname].Value.Scalar; got != "host-1" {
		t.Errorf("value = %q, want host-1", got)
	}
}

// TestCriticalEventsAreNotDebounced: waiting a cycle to report that the
// firewall went down would be the wrong trade in the one case where latency
// actually matters.
func TestCriticalEventsAreNotDebounced(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(protectionData("enabled", "enabled", "enabled"))
	result := h.cycle(protectionData("disabled", "enabled", "enabled"))

	if !hasEvent(result, models.EventFirewallDisabled) {
		t.Fatalf("a critical change waited for confirmation: %v", eventTypes(result))
	}
}

// TestConfiguredDebounceDurationIsHonoured covers an explicit debounce window
// rather than the default next-cycle rule.
func TestConfiguredDebounceDurationIsHonoured(t *testing.T) {
	h := newHarness(t, EventConfig{Debounce: time.Hour, Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})

	// Cycles are 15 minutes apart, so the next four sightings are all still
	// inside a one-hour debounce window.
	for i := 0; i < 4; i++ {
		result := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
		if len(result.Events) != 0 {
			t.Fatalf("cycle %d fired inside the debounce window: %v", i+1, eventTypes(result))
		}
	}

	result := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
	if !hasEvent(result, models.EventHostnameChanged) {
		t.Fatalf("the change never confirmed after the debounce window: %v", eventTypes(result))
	}
}

// ── 13. cooldown ─────────────────────────────────────────────────────────────

func TestCooldownSuppressesRepeatEvents(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Hour, FlapThreshold: 100})

	h.cycle(protectionData("enabled", "enabled", "enabled"))

	first := h.cycle(protectionData("disabled", "enabled", "enabled"))
	if !hasEvent(first, models.EventFirewallDisabled) {
		t.Fatalf("the first change produced %v", eventTypes(first))
	}

	// 15 minutes later, well inside the one-hour cooldown.
	second := h.cycle(protectionData("enabled", "enabled", "enabled"))
	if len(second.Events) != 0 {
		t.Fatalf("a change inside the cooldown produced %v", eventTypes(second))
	}
	if !containsString(second.Suppressed, WatchFirewallState) {
		t.Errorf("Suppressed = %v, want it to name %s", second.Suppressed, WatchFirewallState)
	}

	// The value must still have been committed, or the same transition would
	// be rediscovered every cycle forever.
	if got := h.store.rows[WatchFirewallState].Value.Scalar; got != "enabled" {
		t.Errorf("value = %q, want enabled; a suppressed event must still commit", got)
	}
}

func TestCooldownExpiryAllowsTheNextEvent(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: 20 * time.Minute, FlapThreshold: 100})

	h.cycle(protectionData("enabled", "enabled", "enabled"))
	h.cycle(protectionData("disabled", "enabled", "enabled"))

	// Push well past the cooldown before the next change.
	h.clk.advance(2 * time.Hour)
	result := h.cycle(protectionData("enabled", "enabled", "enabled"))

	if !hasEvent(result, models.EventFirewallRestored) {
		t.Fatalf("a change after the cooldown produced %v", eventTypes(result))
	}
}

// ── 14. flapping ─────────────────────────────────────────────────────────────

// TestFlappingCollapsesIntoOneAggregateEvent: a control toggling every cycle
// would otherwise emit a critical event every cycle, and a storm of critical
// events buries every other alert on the fleet.
func TestFlappingCollapsesIntoOneAggregateEvent(t *testing.T) {
	h := newHarness(t, EventConfig{
		Cooldown:      time.Nanosecond,
		FlapWindow:    4 * time.Hour,
		FlapThreshold: 3,
	})

	h.cycle(protectionData("enabled", "enabled", "enabled"))

	var individual, aggregate int
	states := []string{"disabled", "enabled", "disabled", "enabled", "disabled"}
	for _, state := range states {
		result := h.cycle(protectionData(state, "enabled", "enabled"))
		for _, e := range result.Events {
			if e.EventType == models.EventStateFlapping {
				aggregate++
			} else {
				individual++
			}
		}
	}

	if aggregate != 1 {
		t.Errorf("got %d flapping event(s), want exactly 1", aggregate)
	}
	// The first two transitions are below the threshold and report normally;
	// everything after collapses.
	if individual != 2 {
		t.Errorf("got %d individual event(s), want 2 (the ones below the threshold)", individual)
	}
}

func TestFlappingWindowResets(t *testing.T) {
	h := newHarness(t, EventConfig{
		Cooldown:      time.Nanosecond,
		FlapWindow:    30 * time.Minute,
		FlapThreshold: 3,
	})

	h.cycle(protectionData("enabled", "enabled", "enabled"))

	// Space the changes far enough apart that each opens a fresh window, so
	// the counter never accumulates and no aggregate is ever emitted.
	for i, state := range []string{"disabled", "enabled", "disabled", "enabled"} {
		h.clk.advance(2 * time.Hour)
		result := h.cycle(protectionData(state, "enabled", "enabled"))
		if hasEvent(result, models.EventStateFlapping) {
			t.Fatalf("change %d in a fresh window was reported as flapping", i+1)
		}
	}
}

// ── 15. restart persistence ──────────────────────────────────────────────────

// TestWatchedStateSurvivesRestart rebuilds the engine against the same store,
// which is exactly what an agent restart does. Without persistence every
// restart would look like a first run and swallow the next real change.
func TestWatchedStateSurvivesRestart(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
	h.cycle(protectionData("enabled", "enabled", "enabled"))

	// "Restart": a brand-new engine over the same persisted state.
	restarted := NewEventEngine(DefaultWatches(), h.store, EventConfig{Cooldown: time.Nanosecond})
	h.clk.advance(15 * time.Minute)
	restarted.SetClock(h.clk.now)

	result, err := restarted.Process(testDeviceID, "v3.2.9",
		protectionData("disabled", "enabled", "enabled"),
		map[string]Status{SectionProtection: StatusSuccess})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if len(result.Seeded) != 0 {
		t.Errorf("restart re-seeded %v; the baseline should have been loaded from the store", result.Seeded)
	}
	if !hasEvent(result, models.EventFirewallDisabled) {
		t.Fatalf("the change after restart produced %v, want %s",
			eventTypes(result), models.EventFirewallDisabled)
	}
}

// TestDebounceCandidateSurvivesRestart: a restart between the sighting and the
// confirmation must not lose the candidate, or a hostname change would need two
// cycles after every restart instead of one.
func TestDebounceCandidateSurvivesRestart(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})
	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})

	if state := h.store.rows[WatchHostname]; !state.HasPending() {
		t.Fatal("the pending candidate was not persisted")
	}

	restarted := NewEventEngine(DefaultWatches(), h.store, EventConfig{Cooldown: time.Nanosecond})
	h.clk.advance(15 * time.Minute)
	restarted.SetClock(h.clk.now)

	result, err := restarted.Process(testDeviceID, "v3.2.9",
		SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}},
		map[string]Status{SectionIdentity: StatusSuccess})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !hasEvent(result, models.EventHostnameChanged) {
		t.Fatalf("the candidate did not confirm after restart: %v", eventTypes(result))
	}
}

// TestFlapStateSurvivesRestart: flap counters that reset on restart would let a
// crash-looping device evade flap suppression entirely.
func TestFlapStateSurvivesRestart(t *testing.T) {
	h := newHarness(t, EventConfig{
		Cooldown: time.Nanosecond, FlapWindow: 4 * time.Hour, FlapThreshold: 3,
	})

	h.cycle(protectionData("enabled", "enabled", "enabled"))
	h.cycle(protectionData("disabled", "enabled", "enabled"))
	h.cycle(protectionData("enabled", "enabled", "enabled"))

	if got := h.store.rows[WatchFirewallState].FlapCount; got != 2 {
		t.Fatalf("persisted flap count = %d, want 2", got)
	}

	restarted := NewEventEngine(DefaultWatches(), h.store, EventConfig{
		Cooldown: time.Nanosecond, FlapWindow: 4 * time.Hour, FlapThreshold: 3,
	})
	h.clk.advance(15 * time.Minute)
	restarted.SetClock(h.clk.now)

	result, err := restarted.Process(testDeviceID, "v3.2.9",
		protectionData("disabled", "enabled", "enabled"),
		map[string]Status{SectionProtection: StatusSuccess})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !hasEvent(result, models.EventStateFlapping) {
		t.Fatalf("the flap counter did not survive the restart: %v", eventTypes(result))
	}
}

// ── 16. deterministic event identity ─────────────────────────────────────────

// TestEventIDIsDeterministic pins the contract: the same change computed twice
// yields the same id, so a retried upload after a lost response is idempotent
// at the backend and needs no second deduplication database anywhere.
func TestEventIDIsDeterministic(t *testing.T) {
	const (
		device    = "a1b2c3d4e5f6a7b8"
		eventType = models.EventFirewallDisabled
		watchKey  = WatchFirewallState
		occurred  = "2026-08-21T09:15:00Z"
	)

	first := EventID(device, eventType, watchKey, occurred)
	second := EventID(device, eventType, watchKey, occurred)
	if first != second {
		t.Fatalf("EventID is not deterministic: %q != %q", first, second)
	}
	if len(first) != 64 {
		t.Errorf("EventID length = %d, want 64 hex characters", len(first))
	}

	// Every input must participate, or two different changes could collide and
	// the backend's on-conflict-do-nothing would silently drop one of them.
	varied := map[string]string{
		"device":     EventID("other-device", eventType, watchKey, occurred),
		"event type": EventID(device, models.EventEncryptionDisabled, watchKey, occurred),
		"watch key":  EventID(device, eventType, WatchSecureBootState, occurred),
		"occurred":   EventID(device, eventType, watchKey, "2026-08-21T10:15:00Z"),
	}
	for field, id := range varied {
		if id == first {
			t.Errorf("changing the %s did not change the event id", field)
		}
	}
}

// TestEventIDCannotCollideAcrossFieldBoundaries: without a separator,
// ("ab", "c") and ("a", "bc") would hash identically.
func TestEventIDCannotCollideAcrossFieldBoundaries(t *testing.T) {
	a := EventID("ab", "c", "key", "t")
	b := EventID("a", "bc", "key", "t")
	if a == b {
		t.Fatal("event ids collide across field boundaries")
	}
}

// TestRetriedEventKeepsItsID: the id is computed once and carried in the
// serialised payload, so replaying stored bytes replays the same id.
func TestRetriedEventKeepsItsID(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})
	h.cycle(protectionData("enabled", "enabled", "enabled"))
	result := h.cycle(protectionData("disabled", "enabled", "enabled"))

	if len(result.Events) == 0 {
		t.Fatal("no event produced")
	}
	original := result.Events[0].EventID

	body, err := json.Marshal(result.Events[0])
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var replayed models.TelemetryChangeEvent
	if err := json.Unmarshal(body, &replayed); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if replayed.EventID != original {
		t.Fatalf("event id changed across a round trip: %q -> %q", original, replayed.EventID)
	}
}

// ── occurred_at / detected_at ────────────────────────────────────────────────

// TestDebouncedEventIsDatedWhenTheChangeHappened: conflating the confirmation
// time with the occurrence time would misdate every Normal event by a full
// collection interval.
func TestDebouncedEventIsDatedWhenTheChangeHappened(t *testing.T) {
	h := newHarness(t, EventConfig{Cooldown: time.Nanosecond})

	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-1"}})
	h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
	firstSeen := h.clk.now()

	result := h.cycle(SectionData{SectionIdentity: map[string]any{"hostname": "host-2"}})
	if len(result.Events) == 0 {
		t.Fatal("no event produced")
	}

	evt := result.Events[0]
	if evt.OccurredAt != firstSeen.UTC().Format(time.RFC3339) {
		t.Errorf("occurred_at = %q, want %q (when the new value was first seen)",
			evt.OccurredAt, firstSeen.UTC().Format(time.RFC3339))
	}
	if evt.DetectedAt == evt.OccurredAt {
		t.Error("detected_at equals occurred_at for a debounced event; they are a cycle apart")
	}
}

// ── 23. disabled → zero processing ───────────────────────────────────────────

// TestNilEngineDoesNoWork covers the feature gate at its root: with no engine,
// the cycle behaves exactly as it did before Phase G existed.
func TestNilEngineDoesNoWork(t *testing.T) {
	svc, _, queue := newTestService(t, &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1"},
	})

	if svc.EventEngine() != nil {
		t.Fatal("an engine was configured without anyone asking for one")
	}

	report, err := svc.RunCycle(t.Context(), nil)
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(report.Events) != 0 {
		t.Errorf("events were produced with no engine: %v", report.Events)
	}
	if report.EventsSeeded != 0 || report.EventsSuppressed != 0 {
		t.Error("change-detection counters moved with no engine")
	}
	for _, msg := range queue.messages {
		if msg.Class == ClassEvent {
			t.Error("an event message was queued with no engine")
		}
	}
}

// TestNilStoreNeverEmits: an engine with no store cannot remember a baseline,
// so every cycle is a first observation. Emitting from that would mean an agent
// whose store failed to open would alert on everything, every cycle.
func TestNilStoreNeverEmits(t *testing.T) {
	engine := NewEventEngine(DefaultWatches(), nil, EventConfig{})
	for i := 0; i < 3; i++ {
		result, err := engine.Process(testDeviceID, "v3.2.9",
			protectionData("disabled", "disabled", "disabled"),
			map[string]Status{SectionProtection: StatusSuccess})
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		if len(result.Events) != 0 {
			t.Fatalf("cycle %d emitted %v with no store", i+1, eventTypes(result))
		}
	}
}

// ── config validation ────────────────────────────────────────────────────────

func TestEventConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     EventConfig
		wantErr bool
	}{
		{"zero value", EventConfig{}, false},
		{"sensible", EventConfig{Debounce: time.Minute, Cooldown: 10 * time.Minute, FlapWindow: time.Hour, FlapThreshold: 4}, false},
		{"negative debounce", EventConfig{Debounce: -time.Second}, true},
		{"negative cooldown", EventConfig{Cooldown: -time.Second}, true},
		{"negative flap window", EventConfig{FlapWindow: -time.Second}, true},
		{"negative threshold", EventConfig{FlapThreshold: -1}, true},
		// A threshold of 1 would classify the very first change to any value as
		// flapping, silently replacing every real event with an aggregate.
		{"threshold of one", EventConfig{FlapThreshold: 1}, true},
		// A cooldown longer than the window means the counter always resets
		// before it can reach the threshold, so flapping could never fire.
		{"cooldown exceeds window", EventConfig{Cooldown: 2 * time.Hour, FlapWindow: time.Hour}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestEventConfigDefaults(t *testing.T) {
	got := EventConfig{}.withDefaults()
	if got.Cooldown != DefaultEventCooldown {
		t.Errorf("Cooldown = %v, want %v", got.Cooldown, DefaultEventCooldown)
	}
	if got.FlapWindow != DefaultEventFlapWindow {
		t.Errorf("FlapWindow = %v, want %v", got.FlapWindow, DefaultEventFlapWindow)
	}
	if got.FlapThreshold != DefaultEventFlapThreshold {
		t.Errorf("FlapThreshold = %d, want %d", got.FlapThreshold, DefaultEventFlapThreshold)
	}
	// Zero debounce is meaningful (confirm next cycle), so it must NOT be
	// replaced by a default.
	if got.Debounce != 0 {
		t.Errorf("Debounce = %v, want 0 (the next-cycle rule)", got.Debounce)
	}
}

// ── value model ──────────────────────────────────────────────────────────────

func TestSetValueNormalisesOrderAndDuplicates(t *testing.T) {
	a := SetValue(KindMembership, []string{"c", "a", "b", "a", " ", ""})
	b := SetValue(KindMembership, []string{"b", "c", "a"})

	if !a.Equal(b) {
		t.Fatalf("%v != %v; set order and duplicates must not affect equality", a.Members, b.Members)
	}
	if len(a.Members) != 3 {
		t.Errorf("members = %v, want 3 entries", a.Members)
	}
}

func TestValueRoundTrip(t *testing.T) {
	for _, v := range []Value{
		ScalarValue("enabled"),
		BoolValue(true),
		SetValue(KindMembership, []string{"C:", "D:"}),
	} {
		encoded, err := v.Encode()
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		decoded, err := DecodeValue(encoded)
		if err != nil {
			t.Fatalf("DecodeValue() error = %v", err)
		}
		if !decoded.Equal(v) {
			t.Errorf("round trip changed the value: %+v -> %+v", v, decoded)
		}
	}
}

func TestMembershipKeyRoundTrip(t *testing.T) {
	key := MembershipKey(WatchPrivilegedAccounts, "DOMAIN\\alice")
	base, member, ok := SplitMembershipKey(key)
	if !ok {
		t.Fatal("SplitMembershipKey did not recognise a membership key")
	}
	if base != WatchPrivilegedAccounts {
		t.Errorf("base = %q, want %q", base, WatchPrivilegedAccounts)
	}
	if member != "DOMAIN\\alice" {
		t.Errorf("member = %q, want %q", member, "DOMAIN\\alice")
	}
}

func TestTrustworthyScalar(t *testing.T) {
	untrusted := []string{"", "unknown", "UNKNOWN", " not_present ", "none", "n/a", "unavailable"}
	for _, s := range untrusted {
		if TrustworthyScalar(s) {
			t.Errorf("TrustworthyScalar(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"enabled", "disabled", "host-1", "true", "false"} {
		if !TrustworthyScalar(s) {
			t.Errorf("TrustworthyScalar(%q) = false, want true", s)
		}
	}
}
