package identity

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestCollectorConformsToInterface fails to compile if Collector drifts from
// telemetry.Collector.
var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionIdentity {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionIdentity)
	}
	if c.Section() != tel.SectionIdentity {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionIdentity)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityAlwaysSupported(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != "" {
		t.Errorf("Capability() key = %q, want empty (identity owns no manifest key)", key)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// (WMI on Windows, sysfs on Linux, ioreg on macOS) against actual hardware.
// It follows the same pattern as the existing osinfo WMI collectors
// (internal/osinfo/display/display_windows_test.go): no assumptions about
// specific field values, just that collection does not panic or error and
// produces a well-formed result.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})

	if res.Collector != tel.SectionIdentity || res.Section != tel.SectionIdentity {
		t.Errorf("result collector/section = %q/%q, want %q", res.Collector, res.Section, tel.SectionIdentity)
	}
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want identity.Payload", payload)
	}
	if p.Hostname == "" {
		t.Error("Hostname is empty; os.Hostname() should always return something")
	}

	t.Logf("identity: hostname=%q fqdn=%q manufacturer=%q model=%q serial=%q asset_tag=%q device_uuid=%q machine_id=%q board_serial=%q chassis=%q source=%q",
		p.Hostname, p.FQDN, p.Manufacturer, p.Model, p.SerialNumber, p.AssetTag,
		p.DeviceUUID, p.MachineID, p.BoardSerial, p.ChassisType, res.Source)
}
