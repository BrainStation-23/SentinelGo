package posture

import (
	"context"
	"strconv"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionSecurityPost {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionSecurityPost)
	}
	if c.Section() != tel.SectionSecurityPost {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionSecurityPost)
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

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host.
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
		t.Fatalf("payload type = %T, want posture.Payload", payload)
	}

	pol := p.PasswordPolicy
	t.Logf("posture: min_length=%s min_age=%s max_age=%s lockout_threshold=%s lockout_duration=%s privileged=%v source=%q status=%q",
		intPtrStr(pol.MinLength), intPtrStr(pol.MinAgeDays), intPtrStr(pol.MaxAgeDays),
		intPtrStr(pol.LockoutThreshold), intPtrStr(pol.LockoutDurationMinutes),
		p.PrivilegedAccounts, res.Source, res.Status)
}

func intPtrStr(v *int) string {
	if v == nil {
		return "nil"
	}
	return strconv.Itoa(*v)
}
