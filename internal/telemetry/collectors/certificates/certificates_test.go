package certificates

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionCertificates {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionCertificates)
	}
	if c.Section() != tel.SectionCertificates {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionCertificates)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapability(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyCertificates {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyCertificates)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

func TestSortCertificates(t *testing.T) {
	c := []Certificate{{Thumbprint: "B"}, {Thumbprint: "A"}}
	sortCertificates(c)
	if c[0].Thumbprint != "A" || c[1].Thumbprint != "B" {
		t.Errorf("got %+v", c)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host's actual trust stores.
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
		t.Fatalf("payload type = %T, want certificates.Payload (a bare slice)", payload)
	}
	if len(p) == 0 {
		t.Error("no certificates reported; every real host trusts at least the OS-shipped root CAs")
	}

	t.Logf("certificates: count=%d source=%q status=%q", len(p), res.Source, res.Status)
	if len(p) > 0 {
		t.Logf("  sample: subject=%q issuer=%q thumbprint=%q store=%q",
			p[0].Subject, p[0].Issuer, p[0].Thumbprint, p[0].Store)
	}
}
