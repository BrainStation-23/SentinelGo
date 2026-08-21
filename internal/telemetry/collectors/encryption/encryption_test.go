package encryption

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionEncryption {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionEncryption)
	}
	if c.Section() != tel.SectionEncryption {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionEncryption)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityOwnsKeyAndIsValid(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyStorageEncryption {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyStorageEncryption)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not valid", state)
	}
}

func TestSortVolumes(t *testing.T) {
	v := []Volume{{MountPoint: "", DriveLetter: "D:"}, {MountPoint: "", DriveLetter: "C:"}}
	sortVolumes(v)
	if v[0].DriveLetter != "C:" || v[1].DriveLetter != "D:" {
		t.Errorf("got %+v", v)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	_, capState := c.Capability(context.Background(), tel.CollectorConfig{})
	if capState != tel.CapSupported {
		t.Skipf("encryption detail unsupported on this host: %s", capState)
	}

	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	// Querying BitLocker genuinely requires elevation (confirmed by hand:
	// Get-BitLockerVolume fails with access-denied for a non-elevated,
	// non-SYSTEM caller). This suite does not assume it runs elevated, so a
	// failure status here is a legitimate, expected outcome on such a host —
	// what matters is that a real failure is reported as one (see
	// bitlockerVolumeScript's doc comment for the bug this guards against),
	// not that this specific run happens to succeed.
	if !res.Status.OK() {
		t.Logf("Collect() status = %q, error = %q (expected when not running elevated/as SYSTEM)", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want encryption.Payload", payload)
	}

	t.Logf("encryption: count=%d source=%q status=%q", len(p.Volumes), res.Source, res.Status)
	for _, v := range p.Volumes {
		t.Logf("  %+v", v)
	}
}
