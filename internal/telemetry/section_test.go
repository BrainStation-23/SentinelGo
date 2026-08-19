package telemetry

import (
	"testing"
	"time"
)

// baseTime is a fixed clock so reconciliation is tested by arithmetic rather
// than by sleeping.
var baseTime = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func stateAt(hash string, uploaded time.Time, schemaVersion int) *SectionState {
	return &SectionState{
		Hash:             hash,
		SchemaVersion:    schemaVersion,
		LastCollectedAt:  uploaded,
		LastUploadedAt:   uploaded,
		LastReconciledAt: uploaded,
	}
}

// TestShouldUploadPerSectionReconciliation is the behavioural proof that the
// global one-hour force-resend has been replaced by per-section intervals.
//
// The whole point: a device whose hardware has not changed should re-send that
// hardware once a day, while its security posture still reconciles hourly.
func TestShouldUploadPerSectionReconciliation(t *testing.T) {
	reg := NewDefaultRegistry()

	static, ok := reg.Get(SectionIdentity)
	if !ok {
		t.Fatalf("identity section not registered")
	}
	posture, ok := reg.Get(SectionSecurityPost)
	if !ok {
		t.Fatalf("security_posture section not registered")
	}

	const hash = "same-hash"
	prevStatic := stateAt(hash, baseTime, static.SchemaVersion)
	prevPosture := stateAt(hash, baseTime, posture.SchemaVersion)

	tests := []struct {
		name       string
		spec       SectionSpec
		prev       *SectionState
		elapsed    time.Duration
		wantUpload bool
		wantReason string
	}{
		{"static unchanged after 1h", static, prevStatic, time.Hour, false, ReasonUnchanged},
		{"static unchanged after 23h", static, prevStatic, 23 * time.Hour, false, ReasonUnchanged},
		{"static due at 24h", static, prevStatic, 24 * time.Hour, true, ReasonReconcileDue},
		{"posture unchanged after 59m", posture, prevPosture, 59 * time.Minute, false, ReasonUnchanged},
		{"posture due at 1h", posture, prevPosture, time.Hour, true, ReasonReconcileDue},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ShouldUpload(tc.spec, tc.prev, hash, baseTime.Add(tc.elapsed))
			if got.Upload != tc.wantUpload {
				t.Errorf("upload = %v, want %v (reason %q)", got.Upload, tc.wantUpload, got.Reason)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}

// TestShouldUploadOnChange verifies a content change beats the interval.
func TestShouldUploadOnChange(t *testing.T) {
	reg := NewDefaultRegistry()
	spec, _ := reg.Get(SectionIdentity)
	prev := stateAt("old-hash", baseTime, spec.SchemaVersion)

	got := ShouldUpload(spec, prev, "new-hash", baseTime.Add(time.Minute))
	if !got.Upload || got.Reason != ReasonChanged {
		t.Fatalf("a changed section must upload immediately: upload=%v reason=%q", got.Upload, got.Reason)
	}
}

// TestShouldUploadFirstTime covers a never-uploaded section.
func TestShouldUploadFirstTime(t *testing.T) {
	reg := NewDefaultRegistry()
	spec, _ := reg.Get(SectionIdentity)

	for name, prev := range map[string]*SectionState{
		"nil state":      nil,
		"empty hash":     {Hash: "", SchemaVersion: spec.SchemaVersion},
		"never uploaded": {Hash: "h", SchemaVersion: spec.SchemaVersion, LastCollectedAt: baseTime},
	} {
		t.Run(name, func(t *testing.T) {
			got := ShouldUpload(spec, prev, "h", baseTime)
			if !got.Upload || got.Reason != ReasonFirstUpload {
				t.Fatalf("upload=%v reason=%q, want first_upload", got.Upload, got.Reason)
			}
		})
	}
}

// TestShouldUploadOnSchemaChange ensures a schema bump forces a resend even
// when the content hash is identical, so the backend always sees the new shape.
func TestShouldUploadOnSchemaChange(t *testing.T) {
	reg := NewDefaultRegistry()
	spec, _ := reg.Get(SectionIdentity)
	prev := stateAt("h", baseTime, spec.SchemaVersion+1) // stored under a different version

	got := ShouldUpload(spec, prev, "h", baseTime.Add(time.Minute))
	if !got.Upload || got.Reason != ReasonSchemaChanged {
		t.Fatalf("upload=%v reason=%q, want schema_changed", got.Upload, got.Reason)
	}
}

// TestHealthSectionAlwaysUploads verifies health samples bypass reconciliation.
// Suppressing an unchanged sample would misreport a steady device as idle.
func TestHealthSectionAlwaysUploads(t *testing.T) {
	reg := NewDefaultRegistry()
	spec, ok := reg.Get(SectionHealth)
	if !ok {
		t.Fatalf("health section not registered")
	}
	if spec.Class != ClassHealth {
		t.Fatalf("health section class = %q, want %q", spec.Class, ClassHealth)
	}
	if spec.Fingerprinted() {
		t.Fatal("health must never be fingerprinted: samples change on every read")
	}

	prev := stateAt("identical", baseTime, spec.SchemaVersion)
	got := ShouldUpload(spec, prev, "identical", baseTime.Add(time.Second))
	if !got.Upload || got.Reason != ReasonHealthSample {
		t.Fatalf("upload=%v reason=%q, want health_sample", got.Upload, got.Reason)
	}
}

// TestDueForCollection checks the separate collection cadence.
func TestDueForCollection(t *testing.T) {
	reg := NewDefaultRegistry()
	spec, _ := reg.Get(SectionIdentity) // 6h collect interval

	if !DueForCollection(spec, nil, baseTime) {
		t.Error("a never-collected section must be due")
	}
	prev := &SectionState{LastCollectedAt: baseTime}
	if DueForCollection(spec, prev, baseTime.Add(5*time.Hour)) {
		t.Error("should not be due before the collect interval elapses")
	}
	if !DueForCollection(spec, prev, baseTime.Add(6*time.Hour)) {
		t.Error("should be due once the collect interval elapses")
	}
}

// TestRegistryCoversEveryClass is a smoke test that the default registry is
// coherent: every section has a class, a positive collect interval, and a
// reconcile interval unless it is a health sample.
func TestRegistryCoversEveryClass(t *testing.T) {
	reg := NewDefaultRegistry()
	names := reg.Names()
	if len(names) == 0 {
		t.Fatal("default registry is empty")
	}

	for _, name := range names {
		spec, _ := reg.Get(name)
		if !spec.Class.Valid() {
			t.Errorf("section %q has invalid class %q", name, spec.Class)
		}
		if spec.CollectInterval <= 0 {
			t.Errorf("section %q has non-positive collect interval", name)
		}
		if spec.SchemaVersion < 1 {
			t.Errorf("section %q has schema version %d, want >= 1", name, spec.SchemaVersion)
		}
		if spec.Class == ClassHealth {
			if spec.ReconcileInterval != 0 {
				t.Errorf("health section %q must not have a reconcile interval", name)
			}
			continue
		}
		if spec.ReconcileInterval <= 0 {
			t.Errorf("section %q has non-positive reconcile interval", name)
		}
		if spec.ReconcileInterval < spec.CollectInterval {
			t.Errorf("section %q reconciles (%v) more often than it collects (%v)",
				name, spec.ReconcileInterval, spec.CollectInterval)
		}
	}
}

// TestSoftwareAndServicesNotRegistered documents the deliberate boundary: those
// domains stay on the existing legacy pipeline, untouched by this layer.
func TestSoftwareAndServicesNotRegistered(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, name := range []string{"software", "services"} {
		if _, ok := reg.Get(name); ok {
			t.Errorf("section %q must not be in the telemetry registry: it belongs to the existing pipeline", name)
		}
	}
}
