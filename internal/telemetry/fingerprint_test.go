package telemetry

import (
	"strings"
	"testing"
	"time"
)

// TestFingerprintIgnoresMetaVolatility is the keystone regression test for the
// whole reconciliation design.
//
// CollectorResult and TelemetryHealth carry a duration, a timestamp and a queue
// depth that differ on every cycle. If any of them leaked into a section
// payload, that section would hash differently every time, mark itself changed
// forever, and silently restore the "upload everything every cycle" behaviour
// this layer exists to avoid — a regression that is invisible on one endpoint
// and very expensive across a fleet.
func TestFingerprintIgnoresMetaVolatility(t *testing.T) {
	// Identical system state, collected twice.
	sections := func() SectionData {
		return SectionData{
			SectionIdentity: map[string]any{"hostname": "host-1", "serial": "SN-123"},
			SectionOS:       map[string]any{"name": "Windows 11", "build": "22631"},
		}
	}

	first, err := Fingerprint(sections())
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}

	// Second cycle: same sections, but the envelope metadata differs wildly.
	second, err := Fingerprint(sections())
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}

	env := NewEnvelope(nil, ClassInventory, time.Now())
	env.Meta = &Meta{
		Results: []CollectorResult{{
			Collector:   "identity",
			Section:     SectionIdentity,
			Status:      StatusSuccess,
			CollectedAt: time.Now().Format(time.RFC3339),
			DurationMS:  4211, // different every cycle
		}},
		Health: &TelemetryHealth{PendingQueueDepth: 97, CollectorFailures: 3},
	}

	if changed := Changed(first, second); len(changed) != 0 {
		t.Fatalf("expected zero changed sections across identical collections, got %v", changed)
	}
}

// TestFingerprintRejectsMetaInSection verifies the structural guard: placing
// envelope metadata inside a section must fail loudly rather than quietly
// poisoning change detection.
func TestFingerprintRejectsMetaInSection(t *testing.T) {
	cases := map[string]any{
		"Meta":              Meta{},
		"MetaPtr":           &Meta{},
		"CollectorResult":   CollectorResult{},
		"ResultSlice":       []CollectorResult{{}},
		"TelemetryHealth":   TelemetryHealth{},
		"TelemetryHealthPt": &TelemetryHealth{},
		"DomainHealth":      DomainHealth{},
		"DomainHealthSlice": []DomainHealth{{}},
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Fingerprint(SectionData{SectionIdentity: payload})
			if err == nil {
				t.Fatalf("expected error for metadata %s in a section, got nil", name)
			}
			if !strings.Contains(err.Error(), "Envelope.Meta") {
				t.Fatalf("error should explain where metadata belongs, got: %v", err)
			}
		})
	}
}

// TestFingerprintDetectsRealChange confirms the guard has not made the
// fingerprint insensitive to genuine changes.
func TestFingerprintDetectsRealChange(t *testing.T) {
	before, err := Fingerprint(SectionData{
		SectionIdentity: map[string]any{"hostname": "host-1"},
		SectionOS:       map[string]any{"build": "22631"},
	})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	after, err := Fingerprint(SectionData{
		SectionIdentity: map[string]any{"hostname": "host-1"},
		SectionOS:       map[string]any{"build": "22635"}, // real change
	})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	changed := Changed(before, after)
	if len(changed) != 1 || changed[0] != SectionOS {
		t.Fatalf("expected only %q to change, got %v", SectionOS, changed)
	}
}

// TestChangedIgnoresMissingSections asserts that a section absent from the
// current cycle is not reported as changed. Absence means "not collected", not
// "deleted"; treating it as a change would re-upload stale data.
func TestChangedIgnoresMissingSections(t *testing.T) {
	prev := SectionHashes{SectionIdentity: "aaa", SectionOS: "bbb"}
	cur := SectionHashes{SectionIdentity: "aaa"}

	if changed := Changed(prev, cur); len(changed) != 0 {
		t.Fatalf("expected no changes when a section is simply absent, got %v", changed)
	}
}

// TestHashSectionStableAcrossMapOrder documents that map key ordering does not
// affect the hash, so collectors returning maps are safe.
func TestHashSectionStableAcrossMapOrder(t *testing.T) {
	a, err := HashSection(map[string]any{"z": 1, "a": 2, "m": 3})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b, err := HashSection(map[string]any{"a": 2, "m": 3, "z": 1})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if a != b {
		t.Fatalf("map key order changed the hash: %s vs %s", a, b)
	}
}

// TestHashSectionSliceOrderMatters is a guard-rail documenting the one case
// collector authors must handle themselves: encoding/json preserves slice
// order, so an unsorted list produces a new hash every cycle.
func TestHashSectionSliceOrderMatters(t *testing.T) {
	a, err := HashSection([]string{"one", "two"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b, err := HashSection([]string{"two", "one"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if a == b {
		t.Fatal("expected slice order to affect the hash; collectors must sort list payloads")
	}
}
