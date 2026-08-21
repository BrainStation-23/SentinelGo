package persistence

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionPersistence {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionPersistence)
	}
	if c.Section() != tel.SectionPersistence {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionPersistence)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapability(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyPersistence {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyPersistence)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

func TestSortEntries(t *testing.T) {
	e := []Entry{
		{Type: "scheduled_task", Name: "z"},
		{Type: "registry_run_key", Name: "b"},
		{Type: "registry_run_key", Name: "a"},
	}
	sortEntries(e)
	want := []string{"registry_run_key/a", "registry_run_key/b", "scheduled_task/z"}
	for i, w := range want {
		got := e[i].Type + "/" + e[i].Name
		if got != w {
			t.Errorf("position %d = %q, want %q", i, got, w)
		}
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host's actual persistence mechanisms.
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
		t.Fatalf("payload type = %T, want persistence.Payload (a bare slice)", payload)
	}

	t.Logf("persistence: count=%d source=%q status=%q", len(p), res.Source, res.Status)
	byType := map[string]int{}
	for _, e := range p {
		byType[e.Type]++
	}
	for typ, n := range byType {
		t.Logf("  %s: %d", typ, n)
	}
	if len(p) > 0 {
		t.Logf("  sample: %+v", p[0])
	}
}
