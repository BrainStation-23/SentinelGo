package volumes

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionVolumes {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionVolumes)
	}
	if c.Section() != tel.SectionVolumes {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionVolumes)
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

func TestSortVolumes(t *testing.T) {
	v := []Volume{
		{MountPoint: "", DriveLetter: "D:"},
		{MountPoint: "", DriveLetter: "C:"},
	}
	sortVolumes(v)
	if v[0].DriveLetter != "C:" || v[1].DriveLetter != "D:" {
		t.Errorf("got %+v", v)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host's actual volumes.
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
		t.Fatalf("payload type = %T, want volumes.Payload", payload)
	}
	if len(p.Volumes) == 0 {
		t.Error("no volumes reported; every real host has at least one")
	}

	t.Logf("volumes: count=%d source=%q status=%q", len(p.Volumes), res.Source, res.Status)
	for _, v := range p.Volumes {
		t.Logf("  %+v", v)
	}
}
