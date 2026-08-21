package patches

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionPatches {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionPatches)
	}
	if c.Section() != tel.SectionPatches {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionPatches)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityAlwaysSupported(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyPatchInventory {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyPatchInventory)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

func TestSortUpdates(t *testing.T) {
	u := []Update{
		{Status: "pending", ID: "b"},
		{Status: "installed", ID: "z"},
		{Status: "installed", ID: "a"},
	}
	sortUpdates(u)
	want := []string{"installed/a", "installed/z", "pending/b"}
	for i, w := range want {
		got := u[i].Status + "/" + u[i].ID
		if got != w {
			t.Errorf("position %d = %q, want %q", i, got, w)
		}
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host. Some hosts genuinely have zero pending updates and a
// long installed history (or vice versa), so this only asserts collection
// completes and returns the correct payload shape — not any particular
// count. The chunked-section payload contract (a bare slice, not a struct)
// is exercised structurally via the type assertion itself.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if res.Status.Failed() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want patches.Payload (a bare slice)", payload)
	}

	t.Logf("patches: count=%d source=%q status=%q", len(p), res.Source, res.Status)
	installed, pending := 0, 0
	for _, u := range p {
		switch u.Status {
		case "installed":
			installed++
		case "pending":
			pending++
		}
	}
	t.Logf("  installed=%d pending=%d", installed, pending)
}
