package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

func TestNewReturnsAllThreeBridgedSections(t *testing.T) {
	got := make(map[string]bool)
	for _, c := range New() {
		got[c.Section()] = true
	}

	for _, want := range []string{tel.SectionFirmware, tel.SectionCPU, tel.SectionMemoryModules} {
		if !got[want] {
			t.Errorf("no bridge collector for section %q", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("bridge registered %d sections, want exactly 3 — it must not "+
			"take over sections that already have their own collector", len(got))
	}
}

func TestCollectorIdentities(t *testing.T) {
	for _, c := range New() {
		if c.Name() == "" {
			t.Errorf("collector for section %q has an empty name", c.Section())
		}
		if c.Name() != c.Section() {
			t.Errorf("collector %q fills section %q; the bridge names each "+
				"collector after its section", c.Name(), c.Section())
		}
		if c.SchemaVersion() != 1 {
			t.Errorf("%s SchemaVersion = %d, want 1", c.Name(), c.SchemaVersion())
		}
	}
}

// TestBridgeClaimsNoCapabilityKeys pins a deliberate decision: these three
// sections have no capability key in the manifest, and the bridge must not
// invent one. A key is part of the backend contract.
func TestBridgeClaimsNoCapabilityKeys(t *testing.T) {
	for _, c := range New() {
		key, state := c.Capability(context.Background(), tel.CollectorConfig{})
		if key != "" {
			t.Errorf("%s claims capability key %q; these sections have none and "+
				"adding one changes the backend contract", c.Name(), key)
		}
		if state != tel.CapSupported {
			t.Errorf("%s capability state = %q, want supported", c.Name(), state)
		}
	}
}

// TestCollectorsHonourCancellation pins that a cancelled telemetry cycle does
// not start another round of hardware reads.
func TestCollectorsHonourCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, c := range New() {
		_, res := c.Collect(ctx, tel.CollectorConfig{})
		if res.Status.OK() {
			t.Errorf("%s reported %q for a cancelled context; it collected anyway",
				c.Name(), res.Status)
		}
	}
}

// TestSourceNamesTheBridge is what makes the reuse visible server-side. If one
// of these sections ever gains a collector of its own, Source changes and the
// switch is apparent in the data rather than silent.
func TestSourceNamesTheBridge(t *testing.T) {
	for _, c := range New() {
		_, res := c.Collect(context.Background(), tel.CollectorConfig{})
		if res.Source != sourceLegacyInventory {
			t.Errorf("%s Source = %q, want %q", c.Name(), res.Source, sourceLegacyInventory)
		}
	}

	if got := tel.SanitizeMessage(sourceLegacyInventory); got != sourceLegacyInventory {
		t.Errorf("SanitizeMessage altered the Source string:\n  in:  %q\n  out: %q",
			sourceLegacyInventory, got)
	}
}

// TestEmptyHardwareIsUnsupportedNotFailure pins that a host which genuinely has
// nothing to report — a VM with no DIMMs — does not count against telemetry
// health. A desktop with no battery must not look broken forever, and the same
// reasoning applies here.
func TestEmptyHardwareIsUnsupportedNotFailure(t *testing.T) {
	for _, c := range New() {
		_, res := c.Collect(context.Background(), tel.CollectorConfig{})
		if res.Status.Failed() {
			t.Errorf("%s reported %q on this host; absent hardware is unsupported, "+
				"not a collector failure", c.Name(), res.Status)
		}
	}
}

// ── payload shape ────────────────────────────────────────────────────────────

// TestVolatileFieldsAreExcluded is the fingerprint-stability guarantee.
//
// osinfo collects CPU usage percent and used/free memory alongside the static
// hardware facts. Both change on every read, and these sections are
// fingerprinted at a 6-hour interval, so including either would re-upload the
// section every single cycle. Live load belongs to the health section, which is
// ClassHealth and never fingerprinted.
func TestVolatileFieldsAreExcluded(t *testing.T) {
	cpuJSON, err := json.Marshal(CPUPayload{ModelName: "test"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"usage", "percent", "load"} {
		if strings.Contains(strings.ToLower(string(cpuJSON)), forbidden) {
			t.Errorf("the cpu payload carries a volatile field (%q): %s", forbidden, cpuJSON)
		}
	}

	memJSON, err := json.Marshal(MemoryModulesPayload{Modules: []MemoryModule{{Name: "test"}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"used", "free", "usage"} {
		if strings.Contains(strings.ToLower(string(memJSON)), forbidden) {
			t.Errorf("the memory_modules payload carries a volatile field (%q): %s", forbidden, memJSON)
		}
	}
}

// TestSortModulesIsDeterministic pins the sort. WMI and system_profiler do not
// guarantee a stable enumeration order between reads.
func TestSortModulesIsDeterministic(t *testing.T) {
	a := []MemoryModule{
		{Slot: "DIMM_B1", Name: "Physical Memory", CapacityBytes: 17179869184, Serial: "SN2"},
		{Slot: "DIMM_A1", Name: "Physical Memory", CapacityBytes: 17179869184, Serial: "SN1"},
		{Slot: "DIMM_A2", Name: "Physical Memory", CapacityBytes: 8589934592, Serial: "SN3"},
	}
	b := []MemoryModule{a[2], a[0], a[1]}

	SortModules(a)
	SortModules(b)

	first, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("SortModules is order-dependent, so an unchanged set of DIMMs "+
			"would hash differently every cycle:\n  %s\n  %s", first, second)
	}
	if a[0].Slot != "DIMM_A1" {
		t.Errorf("modules are not ordered by slot: %s", first)
	}
}

// TestMemoryModulesRespectsMaxItems pins the bound.
func TestMemoryModulesRespectsMaxItems(t *testing.T) {
	payload, _ := (&MemoryModulesCollector{}).Collect(
		context.Background(), tel.CollectorConfig{MaxItems: 1})

	p, ok := payload.(MemoryModulesPayload)
	if !ok {
		t.Fatalf("payload type = %T, want MemoryModulesPayload", payload)
	}
	if len(p.Modules) > 1 {
		t.Errorf("collected %d modules with MaxItems=1", len(p.Modules))
	}
}

// TestPayloadTypesAreStable pins the wire shape: absent values are omitted
// rather than serialised as zero, so "this host did not report a clock speed"
// is distinguishable from "0 MHz".
func TestPayloadTypesAreStable(t *testing.T) {
	b, err := json.Marshal(FirmwarePayload{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("an empty firmware payload serialised as %s, want {}", b)
	}

	b, err = json.Marshal(MemoryModule{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("an empty memory module serialised as %s, want {}", b)
	}

	// Modules is not omitempty: an empty list is a meaningful answer ("this
	// host exposes no per-DIMM detail") and must appear in the payload.
	b, err = json.Marshal(MemoryModulesPayload{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"modules"`) {
		t.Errorf("memory_modules payload omitted the modules key: %s", b)
	}
}
