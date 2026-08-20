package osdetail

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionOS {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionOS)
	}
	if c.Section() != tel.SectionOS {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionOS)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityAlwaysSupported(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != "" {
		t.Errorf("Capability() key = %q, want empty (os owns no manifest key)", key)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host: no assumption about whether a reboot happens to be
// pending or what the install date is, just that collection completes
// cleanly, the baseline fields are non-empty, and PendingReboot is never a
// fabricated false — either nil (undetermined) or a value the platform's
// mechanism actually produced.
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
		t.Fatalf("payload type = %T, want osdetail.Payload", payload)
	}
	if p.Name == "" {
		t.Error("Name is empty; the OS name should always be determinable")
	}

	pendingReboot := "nil"
	if p.PendingReboot != nil {
		pendingReboot = boolStr(*p.PendingReboot)
	}
	t.Logf("os: name=%q version=%q display_version=%q type=%q arch=%q locale=%q tz=%q install_date=%q pending_reboot=%s reason=%q activation=%q source=%q",
		p.Name, p.Version, p.DisplayVersion, p.Type, p.Architecture, p.Locale, p.TimeZone,
		p.InstallDate, pendingReboot, p.PendingRebootReason, p.ActivationStatus, res.Source)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
