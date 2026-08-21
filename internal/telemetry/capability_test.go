package telemetry

import "testing"

// TestCapabilityStatesAreDistinct is the reason this type exists: four ways of
// having no data must not collapse into one.
//
// Concretely, on a desktop VM with no TPM and no battery an operator must be
// able to tell "this machine has no battery" (nothing to do) from "the battery
// collector is switched off" (flip a config flag) from "this OS cannot report
// it" (nothing will ever change) from "the firmware hides it" (a driver issue).
func TestCapabilityStatesAreDistinct(t *testing.T) {
	m := NewCapabilityManifest()

	// A desktop VM: no battery hardware, no TPM chip.
	m.Set(CapKeyBatteryDetail, CapNotPresent)
	m.Set(CapKeyTPM, CapNotPresent)
	// Process collection is switched off by policy.
	m.Set(CapKeyProcesses, CapDisabled)
	m.Set(CapKeyProcessesCmdline, CapDisabled)
	// The disk controller hides SMART from the guest.
	m.Set(CapKeyStorageSMART, CapUnsupported)
	// Secure Boot is readable and was collected.
	m.Set(CapKeySecureBoot, CapSupported)

	tests := map[string]CapabilityState{
		CapKeyBatteryDetail:    CapNotPresent,
		CapKeyTPM:              CapNotPresent,
		CapKeyProcesses:        CapDisabled,
		CapKeyProcessesCmdline: CapDisabled,
		CapKeyStorageSMART:     CapUnsupported,
		CapKeySecureBoot:       CapSupported,
	}
	for key, want := range tests {
		if got := m.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	// The five "no data" states must be mutually distinct values.
	distinct := []CapabilityState{
		CapNotPresent, CapUnsupported, CapDisabled, CapUnavailableOS, CapNotCollected,
	}
	for i := range distinct {
		for j := i + 1; j < len(distinct); j++ {
			if distinct[i] == distinct[j] {
				t.Errorf("states %q and %q collide", distinct[i], distinct[j])
			}
		}
	}
}

// TestNewCapabilityManifestDefaultsToNotCollected ensures a capability nobody
// claimed reports a defined state instead of silently vanishing — and that the
// state it reports is one about the AGENT, not about the operating system.
//
// The default used to be unavailable_on_os, which is why a Windows 11 endpoint
// reported secure_boot as something Windows could not provide. Windows can; no
// collector had claimed the key. An operator reading unavailable_on_os stops
// looking, so the wrong default did not just mislabel the gap, it hid it.
func TestNewCapabilityManifestDefaultsToNotCollected(t *testing.T) {
	m := NewCapabilityManifest()
	for _, key := range AllCapabilityKeys() {
		if got := m.Get(key); got != CapNotCollected {
			t.Errorf("%s defaulted to %q, want %q", key, got, CapNotCollected)
		}
	}
}

// TestCapabilityManifestRejectsInvalidState verifies a collector bug cannot put
// an unrecognised value on the wire.
func TestCapabilityManifestRejectsInvalidState(t *testing.T) {
	m := NewCapabilityManifest()
	m.Set(CapKeyTPM, CapabilityState("totally-made-up"))
	if got := m.Get(CapKeyTPM); got != CapNotCollected {
		t.Fatalf("invalid state was accepted: %q", got)
	}
}

// TestCapabilityManifestUnknownKey covers reads of keys never set.
func TestCapabilityManifestUnknownKey(t *testing.T) {
	m := CapabilityManifest{}
	if got := m.Get("not.a.real.capability"); got != CapNotCollected {
		t.Fatalf("unknown key = %q, want %q", got, CapNotCollected)
	}
}

// TestCapabilityManifestCloneIsIndependent guards against a later cycle
// mutating a manifest already handed to the uploader.
func TestCapabilityManifestCloneIsIndependent(t *testing.T) {
	original := NewCapabilityManifest()
	original.Set(CapKeyTPM, CapSupported)

	clone := original.Clone()
	clone.Set(CapKeyTPM, CapNotPresent)

	if original.Get(CapKeyTPM) != CapSupported {
		t.Fatal("mutating the clone changed the original")
	}
}

// TestHealthStateForCapabilityWins verifies that absent hardware reports as
// not_applicable forever rather than accumulating failures.
func TestHealthStateForCapabilityWins(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		cap    CapabilityState
		want   string
	}{
		{"no battery", StatusUnsupported, CapNotPresent, HealthNotApplicable},
		{"disabled by config", StatusUnsupported, CapDisabled, HealthDisabled},
		{"os cannot provide", StatusUnsupported, CapUnavailableOS, HealthNotApplicable},
		{"no collector ships for it", StatusUnsupported, CapNotCollected, HealthNotApplicable},
		{"collected fine", StatusSuccess, CapSupported, HealthHealthy},
		{"partial data", StatusPartial, CapSupported, HealthPartial},
		{"needs elevation", StatusPermissionDenied, CapSupported, HealthPermissionDenied},
		{"timed out", StatusTimeout, CapSupported, HealthFailing},
		{"errored", StatusError, CapSupported, HealthFailing},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HealthStateFor(tc.status, tc.cap); got != tc.want {
				t.Errorf("HealthStateFor(%q, %q) = %q, want %q", tc.status, tc.cap, got, tc.want)
			}
		})
	}
}

// TestHealthTrackerDoesNotPenaliseAbsentHardware verifies the failure counter
// only rises for genuine faults. Otherwise every desktop would look unhealthy
// forever for lacking a battery.
func TestHealthTrackerDoesNotPenaliseAbsentHardware(t *testing.T) {
	tracker := NewHealthTracker()

	for i := 0; i < 5; i++ {
		tracker.Observe(CollectorResult{
			Collector: "battery",
			Section:   SectionHealth,
			Status:    StatusUnsupported,
		}, CapNotPresent)
	}

	report := tracker.Report()
	if report.CollectorFailures != 0 {
		t.Fatalf("absent hardware counted %d failures, want 0", report.CollectorFailures)
	}
	if len(report.Domains) != 1 || report.Domains[0].State != HealthNotApplicable {
		t.Fatalf("expected a single not_applicable domain, got %+v", report.Domains)
	}
	if report.Domains[0].ConsecutiveFailures != 0 {
		t.Fatalf("consecutive failures = %d, want 0", report.Domains[0].ConsecutiveFailures)
	}
}

// TestHealthTrackerCountsRealFailures is the complement: genuine faults must be
// visible and must reset on recovery.
func TestHealthTrackerCountsRealFailures(t *testing.T) {
	tracker := NewHealthTracker()

	for i := 0; i < 3; i++ {
		tracker.Observe(CollectorResult{
			Collector: "certificates",
			Section:   SectionCertificates,
			Status:    StatusPermissionDenied,
			Error:     ReasonPermissionDenied,
		}, CapSupported)
	}

	report := tracker.Report()
	if report.CollectorFailures != 3 {
		t.Fatalf("collector failures = %d, want 3", report.CollectorFailures)
	}
	if report.Domains[0].State != HealthPermissionDenied {
		t.Fatalf("state = %q, want %q", report.Domains[0].State, HealthPermissionDenied)
	}
	if report.Domains[0].ConsecutiveFailures != 3 {
		t.Fatalf("consecutive failures = %d, want 3", report.Domains[0].ConsecutiveFailures)
	}

	// Recovery clears the streak and the error.
	tracker.Observe(CollectorResult{
		Collector:   "certificates",
		Section:     SectionCertificates,
		Status:      StatusSuccess,
		CollectedAt: "2026-08-19T12:00:00Z",
	}, CapSupported)

	report = tracker.Report()
	if report.Domains[0].ConsecutiveFailures != 0 {
		t.Fatalf("consecutive failures after recovery = %d, want 0", report.Domains[0].ConsecutiveFailures)
	}
	if report.Domains[0].LastError != "" {
		t.Fatalf("last error should clear on recovery, got %q", report.Domains[0].LastError)
	}
	if report.Domains[0].State != HealthHealthy {
		t.Fatalf("state = %q, want %q", report.Domains[0].State, HealthHealthy)
	}
}

// TestHealthTrackerReportsDroppedTelemetry ensures queue eviction is always
// visible rather than a silent loss.
func TestHealthTrackerReportsDroppedTelemetry(t *testing.T) {
	tracker := NewHealthTracker()
	tracker.AddDropped(7)
	tracker.SetQueueDepth(42)

	report := tracker.Report()
	if report.DroppedEventCount != 7 {
		t.Errorf("dropped = %d, want 7", report.DroppedEventCount)
	}
	if report.PendingQueueDepth != 42 {
		t.Errorf("queue depth = %d, want 42", report.PendingQueueDepth)
	}
}
