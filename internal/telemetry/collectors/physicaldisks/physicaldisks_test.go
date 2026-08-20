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
