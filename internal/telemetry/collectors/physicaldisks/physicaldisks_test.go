package physicaldisks

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionPhysicalDisks {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionPhysicalDisks)
	}
	if c.Section() != tel.SectionPhysicalDisks {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionPhysicalDisks)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityAlwaysSupported(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != "" {
		t.Errorf("Capability() key = %q, want empty", key)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

func TestSortDisks(t *testing.T) {
	d := []Disk{{ID: "sdb"}, {ID: "sda"}, {ID: "nvme0n1"}}
	sortDisks(d)
	want := []string{"nvme0n1", "sda", "sdb"}
	for i, w := range want {
		if d[i].ID != w {
			t.Errorf("position %d = %q, want %q", i, d[i].ID, w)
		}
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host's actual disks.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want physicaldisks.Payload", payload)
	}
	if len(p.Disks) == 0 {
		t.Error("no disks reported; every real host should have at least one")
	}

	t.Logf("physical_disks: count=%d source=%q status=%q", len(p.Disks), res.Source, res.Status)
	for _, d := range p.Disks {
		t.Logf("  %+v smart=%+v", d, d.SMART)
	}
}

// TestSMARTCapabilityIsClaimed is the regression test for a reporting
// inconsistency found while validating the capability manifest on a real
// Windows host: this collector gathers SMART attributes, but nothing claimed
// CapKeyStorageSMART, so the key kept the manifest default. The backend was
// told "this build ships no collector for it" while the physical_disks section
// carried temperature, power-on hours and wear.
//
// This is the same class of bug as the previously-unclaimed secure_boot and tpm
// keys; see TestPreviouslyUnclaimedKeysNowHaveOwners in the collectors package.
func TestSMARTCapabilityIsClaimed(t *testing.T) {
	c := New()

	reporter, ok := any(c).(tel.SubCapabilityReporter)
	if !ok {
		t.Fatal("physical_disks does not implement SubCapabilityReporter, so " +
			"storage.smart has no owner and reports the manifest default")
	}

	subs := reporter.SubCapabilities(context.Background(), tel.CollectorConfig{})
	state, claimed := subs[tel.CapKeyStorageSMART]
	if !claimed {
		t.Fatalf("storage.smart is not claimed; got keys %v", subs)
	}
	if state == tel.CapNotCollected {
		t.Error("storage.smart reports not_collected from the collector that " +
			"actually collects it")
	}
	if !state.Valid() {
		t.Errorf("storage.smart reports an invalid state %q", state)
	}
}

// TestSMARTCapabilityDescribesTheMechanismNotTheResult pins the distinction the
// state is meant to carry. A disk with no wear percentage — a spinning HDD, a
// USB enclosure, a virtual disk — is a nil field within a supported capability.
// Only the mechanism being absent makes the capability unsupported.
func TestSMARTCapabilityDescribesTheMechanismNotTheResult(t *testing.T) {
	state := smartCapability(context.Background())

	switch state {
	case tel.CapSupported, tel.CapUnsupported:
		// Both are legitimate and depend on what this host has installed.
	default:
		t.Errorf("smartCapability = %q; the mechanism is either present "+
			"(supported) or absent (unsupported), never anything else", state)
	}
}

// TestSMARTCapabilityDoesNotGateTheDiskList pins that claiming the sub-key did
// not accidentally turn SMART into a section-level gate. A host without
// smartctl must still get its disk inventory.
func TestSMARTCapabilityDoesNotGateTheDiskList(t *testing.T) {
	key, state := New().Capability(context.Background(), tel.CollectorConfig{})
	if key != "" {
		t.Errorf("physical_disks claims primary capability key %q; SMART must "+
			"stay a sub-capability or a missing smartctl would discard the "+
			"whole disk list", key)
	}
	if state != tel.CapSupported {
		t.Errorf("primary capability = %q, want supported: disk enumeration "+
			"works on every supported platform", state)
	}
}
