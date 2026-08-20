package virtualization

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionVirtualization {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionVirtualization)
	}
	if c.Section() != tel.SectionVirtualization {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionVirtualization)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityOwnsKey(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyVirtualization {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyVirtualization)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not a valid CapabilityState", state)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against actual hardware, following the pattern established by the existing
// osinfo WMI collector tests: no assumption about whether this particular
// test host is a VM, just that collection completes cleanly.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	_, capState := c.Capability(context.Background(), tel.CollectorConfig{})
	if capState != tel.CapSupported {
		t.Skipf("virtualization detection unsupported on this host: %s", capState)
	}

	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want virtualization.Payload", payload)
	}

	t.Logf("virtualization: is_virtual=%v hypervisor=%q cloud_platform=%q source=%q",
		p.IsVirtual, p.Hypervisor, p.CloudPlatform, res.Source)
}
