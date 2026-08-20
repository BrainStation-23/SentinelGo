package network

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionNetwork {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionNetwork)
	}
	if c.Section() != tel.SectionNetwork {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionNetwork)
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

func TestSortInterfaces(t *testing.T) {
	ifaces := []Interface{{Name: "Wi-Fi"}, {Name: "Ethernet"}}
	sortInterfaces(ifaces)
	if ifaces[0].Name != "Ethernet" || ifaces[1].Name != "Wi-Fi" {
		t.Errorf("got %+v", ifaces)
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host's actual interfaces.
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
		t.Fatalf("payload type = %T, want network.Payload", payload)
	}

	proxyEnabled := "nil"
	if p.ProxyEnabled != nil {
		proxyEnabled = boolStr(*p.ProxyEnabled)
	}
	t.Logf("network: interfaces=%d proxy_enabled=%s proxy_server=%q source=%q status=%q",
		len(p.Interfaces), proxyEnabled, p.ProxyServer, res.Source, res.Status)
	for _, i := range p.Interfaces {
		physical := "nil"
		if i.IsPhysical != nil {
			physical = boolStr(*i.IsPhysical)
		}
		dhcp := "nil"
		if i.DHCPEnabled != nil {
			dhcp = boolStr(*i.DHCPEnabled)
		}
		t.Logf("  %s mtu=%d physical=%s dhcp=%s vpn=%v up=%v ipv4=%v gw=%q",
			i.Name, i.MTU, physical, dhcp, i.IsVPN, i.IsUp, i.IPv4Addresses, i.DefaultGateway)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
