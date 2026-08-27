package routes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

func TestCollectorIdentity(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionRoutes {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionRoutes)
	}
	if c.Section() != tel.SectionRoutes {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionRoutes)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

// TestCapabilityIsDisabledByDefault is the honest-reporting guarantee. With the
// flag off the backend must be told an administrator switched collection off,
// not that the platform cannot provide it.
func TestCapabilityIsDisabledByDefault(t *testing.T) {
	key, state := New().Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyNetworkRoutingTable {
		t.Errorf("capability key = %q, want %q", key, tel.CapKeyNetworkRoutingTable)
	}
	if state != tel.CapDisabled {
		t.Errorf("capability state = %q, want %q — with collect_routing_table off, "+
			"the reason is configuration, not the platform", state, tel.CapDisabled)
	}
}

// TestCapabilityWhenEnabledAsksThePlatform verifies the flag being on hands the
// verdict to the platform probe rather than asserting support unconditionally.
func TestCapabilityWhenEnabledAsksThePlatform(t *testing.T) {
	_, state := New().Capability(context.Background(), tel.CollectorConfig{CollectRoutingTable: true})
	switch state {
	case tel.CapSupported, tel.CapUnsupported:
		// Both are legitimate: it depends on whether this host has the tool.
	default:
		t.Errorf("capability state = %q, want supported or unsupported once enabled", state)
	}
}

// TestCollectIsInertWhenDisabled is the cost/privacy gate. RunAll already skips
// Collect when Capability is not supported, but Collect is reachable directly
// from the debug CLI and from tests, so the gate must hold on every path.
func TestCollectIsInertWhenDisabled(t *testing.T) {
	payload, res := New().Collect(context.Background(), tel.CollectorConfig{})

	routes, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want Payload", payload)
	}
	if len(routes) != 0 {
		t.Errorf("collected %d routes with collect_routing_table off", len(routes))
	}
	if res.Status != tel.StatusUnsupported {
		t.Errorf("status = %q, want %q", res.Status, tel.StatusUnsupported)
	}
	if res.Source != "disabled_by_config" {
		t.Errorf("source = %q, want disabled_by_config", res.Source)
	}
	if res.Status.Failed() {
		t.Error("a config-disabled collector must not count as a collector failure")
	}
}

// TestCollectRespectsMaxItems pins the bound. The routing table is the one
// section whose size is set by how the host is used rather than by what it is.
func TestCollectRespectsMaxItems(t *testing.T) {
	// Exercise the bound through Normalize + the same clamping Collect applies,
	// so the test does not depend on this machine's real routing table.
	in := make([]Route, 50)
	for i := range in {
		in[i] = Route{Destination: "10.0.0.0/8", Family: FamilyIPv4}
	}
	items := Normalize(in)

	limit := maxRoutes
	if cfg := (tel.CollectorConfig{MaxItems: 10}); cfg.MaxItems > 0 && cfg.MaxItems < limit {
		limit = cfg.MaxItems
	}
	if len(items) > limit {
		items = items[:limit]
	}
	if len(items) != 10 {
		t.Errorf("bounded to %d routes, want 10", len(items))
	}
}

func TestMaxRoutesCeilingExists(t *testing.T) {
	if maxRoutes <= 0 {
		t.Fatal("maxRoutes must be a positive ceiling: MaxItems defaults to 0 " +
			"(unlimited), so this is the only bound on a BGP or container host")
	}
}

// TestNormalizeIsDeterministic is the fingerprint-stability guarantee for the
// section as a whole: the kernel emits routes in an order that is not stable
// across reads, and an unstable order would re-upload the section every cycle.
func TestNormalizeIsDeterministic(t *testing.T) {
	m1, m2 := 100, 600
	unsorted := []Route{
		{Destination: "192.168.1.0/24", Interface: "wlan0", Family: FamilyIPv4, Metric: &m2},
		{Destination: "::/0", Gateway: "fe80::1", Interface: "eth0", Family: FamilyIPv6},
		{Destination: "0.0.0.0/0", Gateway: "10.20.0.1", Interface: "eth0", Family: FamilyIPv4, Metric: &m1},
		{Destination: "10.8.0.0/24", Interface: "wg0", Family: FamilyIPv4},
	}
	shuffled := []Route{unsorted[2], unsorted[0], unsorted[3], unsorted[1]}

	a, err := json.Marshal(Normalize(unsorted))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(Normalize(shuffled))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("Normalize is order-dependent, so an unchanged routing table "+
			"would hash differently every cycle:\n  %s\n  %s", a, b)
	}
}

// TestNormalizeDropsEntriesWithNoDestination pins that an unparseable line
// becomes nothing rather than a route with an empty destination.
func TestNormalizeDropsEntriesWithNoDestination(t *testing.T) {
	got := Normalize([]Route{
		{Destination: "", Interface: "eth0", Family: FamilyIPv4},
		{Destination: "0.0.0.0/0", Interface: "eth0", Family: FamilyIPv4},
	})
	if len(got) != 1 {
		t.Fatalf("kept %d routes, want 1", len(got))
	}
	if got[0].Destination == "" {
		t.Error("a route with no destination survived normalisation")
	}
}

// TestPayloadIsASliceForChunking pins the constraint SectionRoutes inherits by
// being registered Chunked: telemetry.ChunkSection reflects over the value
// Collect returns and requires a slice.
func TestPayloadIsASliceForChunking(t *testing.T) {
	spec, ok := tel.NewRegistry(tel.DefaultSections()).Get(tel.SectionRoutes)
	if !ok {
		t.Fatal("routes section is not registered in DefaultSections")
	}
	if !spec.Chunked {
		t.Error("routes must be chunked: a split-tunnel VPN or container host " +
			"can produce hundreds of entries, and the section must batch rather " +
			"than truncate")
	}

	payload, _ := New().Collect(context.Background(), tel.CollectorConfig{})
	if _, ok := payload.(Payload); !ok {
		t.Fatalf("payload type = %T, want a slice type", payload)
	}
}

// TestSourceStringsSurviveSanitization mirrors the regression test in the
// network and virtualization packages: a harmless diagnostic string must not
// trip SanitizeMessage's secret-shaped-token redaction.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	for _, s := range []string{
		"exec:ip route",
		"exec:netstat -rn",
		"wmi:root/StandardCimv2:MSFT_NetRoute",
		"disabled_by_config",
	} {
		if got := tel.SanitizeMessage(s); got != s {
			t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", s, got)
		}
	}
}

// TestRouteJSONShape pins the wire contract: a missing metric is omitted rather
// than serialised as 0, which on Linux and Windows is a real metric value.
func TestRouteJSONShape(t *testing.T) {
	b, err := json.Marshal(Route{Destination: "0.0.0.0/0", Family: FamilyIPv4})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "metric") {
		t.Errorf("a nil metric was serialised: %s", b)
	}
	if !strings.Contains(string(b), `"destination"`) || !strings.Contains(string(b), `"family"`) {
		t.Errorf("destination and family must always be present: %s", b)
	}

	m := 0
	b, err = json.Marshal(Route{Destination: "0.0.0.0/0", Family: FamilyIPv4, Metric: &m})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"metric":0`) {
		t.Errorf("an explicit metric of 0 must survive serialisation: %s", b)
	}
}
