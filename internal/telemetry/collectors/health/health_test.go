package health

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionHealth {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionHealth)
	}
	if c.Section() != tel.SectionHealth {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionHealth)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityOwnsBatteryKey(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyBatteryDetail {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyBatteryDetail)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not valid", state)
	}
}

func TestSystemVolumePath(t *testing.T) {
	if got := systemVolumePath(); got == "" {
		t.Error("systemVolumePath() returned empty")
	}
}

// TestCollect_Integration exercises the real gopsutil- and platform-specific
// gathering code against this host. Health is never fingerprinted or
// reconciled (see the package doc), so there is no "unchanged" case to test
// — only that a sample completes and reports sane structure.
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
		t.Fatalf("payload type = %T, want health.Payload", payload)
	}

	if p.CPUPercent < 0 || p.CPUPercent > 100 {
		t.Errorf("CPUPercent = %v, want 0-100", p.CPUPercent)
	}
	if p.MemoryPercent <= 0 || p.MemoryPercent > 100 {
		t.Errorf("MemoryPercent = %v, want (0,100]", p.MemoryPercent)
	}
	if p.UptimeSeconds == 0 {
		t.Error("UptimeSeconds = 0, want a real uptime")
	}

	batteryDesc := "none"
	if p.Battery != nil {
		batteryDesc = "present=" + boolStr(p.Battery.Present)
	}
	t.Logf("health: cpu=%.1f%% mem=%.1f%% disk=%.1f%% uptime=%ds battery=%s source=%q status=%q",
		p.CPUPercent, p.MemoryPercent, p.DiskPercent, p.UptimeSeconds, batteryDesc, res.Source, res.Status)
	if p.Battery != nil && p.Battery.Present {
		t.Logf("  battery detail: %+v", p.Battery)
		if p.Battery.DesignCapacityMWh != nil {
			t.Logf("    design_capacity_mwh=%d", *p.Battery.DesignCapacityMWh)
		}
		if p.Battery.FullChargeCapacityMWh != nil {
			t.Logf("    full_charge_capacity_mwh=%d", *p.Battery.FullChargeCapacityMWh)
		}
		if p.Battery.CycleCount != nil {
			t.Logf("    cycle_count=%d", *p.Battery.CycleCount)
		}
		if p.Battery.PercentRemaining != nil {
			t.Logf("    percent_remaining=%.1f", *p.Battery.PercentRemaining)
		}
		if p.Battery.Charging != nil {
			t.Logf("    charging=%v", *p.Battery.Charging)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
