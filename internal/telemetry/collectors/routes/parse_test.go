package routes

import (
	"encoding/json"
	"strings"
	"testing"
)

// Captured `ip route show` output from a laptop with Wi-Fi, a wired dock, a
// WireGuard tunnel and Docker running.
const ipRouteV4Sample = `default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.42 metric 600
default via 10.20.0.1 dev eth0 proto static metric 100
10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.2
169.254.0.0/16 dev eth0 scope link metric 1000
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42 metric 600
`

// IPv6 output, including the transient `expires` countdown on a
// router-advertised default route and a multipath continuation line.
const ipRouteV6Sample = `::1 dev lo proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1%eth0 dev eth0 proto ra metric 1024 expires 1793sec hoplimit 64 pref medium
2001:db8::/32 proto static metric 1024 pref medium
	nexthop via 2001:db8::1 dev eth0 weight 1
`

func TestParseIPRouteV4(t *testing.T) {
	got := parseIPRoute(ipRouteV4Sample, FamilyIPv4)
	if len(got) != 6 {
		t.Fatalf("parsed %d routes, want 6: %+v", len(got), got)
	}

	first := got[0]
	if first.Destination != "0.0.0.0/0" {
		t.Errorf("default route destination = %q, want %q — the wire format must "+
			"carry the real prefix, not the platform's word for it", first.Destination, "0.0.0.0/0")
	}
	if first.Gateway != "192.168.1.1" {
		t.Errorf("gateway = %q, want 192.168.1.1", first.Gateway)
	}
	if first.Interface != "wlan0" {
		t.Errorf("interface = %q, want wlan0", first.Interface)
	}
	if first.Source != "dhcp" {
		t.Errorf("source = %q, want dhcp", first.Source)
	}
	if first.Metric == nil || *first.Metric != 600 {
		t.Errorf("metric = %v, want 600", first.Metric)
	}
	if first.Family != FamilyIPv4 {
		t.Errorf("family = %q, want %q", first.Family, FamilyIPv4)
	}
}

// TestParseIPRouteOnLinkHasNoGateway pins that a directly-connected route
// reports an empty gateway rather than a placeholder.
func TestParseIPRouteOnLinkHasNoGateway(t *testing.T) {
	got := parseIPRoute("10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.2\n", FamilyIPv4)
	if len(got) != 1 {
		t.Fatalf("parsed %d routes, want 1", len(got))
	}
	if got[0].Gateway != "" {
		t.Errorf("gateway = %q, want empty — an on-link route has no next hop", got[0].Gateway)
	}
	if got[0].Metric != nil {
		t.Errorf("metric = %v, want nil — the line states none, and 0 is a real "+
			"metric that a missing value must not collapse into", *got[0].Metric)
	}
}

func TestParseIPRouteV6(t *testing.T) {
	got := parseIPRoute(ipRouteV6Sample, FamilyIPv6)

	var def *Route
	for i := range got {
		if got[i].Destination == "::/0" {
			def = &got[i]
		}
	}
	if def == nil {
		t.Fatalf("no default route parsed from IPv6 sample: %+v", got)
	}
	if def.Gateway != "fe80::1" {
		t.Errorf("gateway = %q, want fe80::1 — the %%eth0 zone belongs in the "+
			"interface field, not the address", def.Gateway)
	}
	if def.Source != "ra" {
		t.Errorf("source = %q, want ra", def.Source)
	}

	// A bare host address gets its full-length prefix.
	var loopback bool
	for _, r := range got {
		if r.Destination == "::1/128" {
			loopback = true
		}
	}
	if !loopback {
		t.Errorf("::1 was not normalised to ::1/128: %+v", got)
	}
}

// TestParseIPRouteExcludesTransientFields is the fingerprint-stability
// guarantee. `expires` counts down on every read, so if it ever reached the
// payload a static IPv6 default route would change its fingerprint on every
// cycle and re-upload the section forever.
func TestParseIPRouteExcludesTransientFields(t *testing.T) {
	first := parseIPRoute(ipRouteV6Sample, FamilyIPv6)
	second := parseIPRoute(
		strings.Replace(ipRouteV6Sample, "expires 1793sec", "expires 12sec", 1),
		FamilyIPv6,
	)

	if len(first) != len(second) {
		t.Fatalf("route count changed with the expiry timer: %d vs %d", len(first), len(second))
	}
	// Compared as serialised JSON rather than field by field, because that is
	// exactly what telemetry.Fingerprint hashes — Route holds a *int metric, so
	// a struct comparison would compare pointer identities and fail regardless
	// of the values behind them.
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("the payload changed only because the expiry countdown moved, so "+
			"this section would re-upload on every cycle:\n  %s\n  %s", a, b)
	}
}

// TestParseIPRouteSkipsMultipathContinuation pins that a "nexthop" line is not
// mistaken for a route of its own.
func TestParseIPRouteSkipsMultipathContinuation(t *testing.T) {
	for _, r := range parseIPRoute(ipRouteV6Sample, FamilyIPv6) {
		if strings.HasPrefix(r.Destination, "nexthop") {
			t.Errorf("a multipath continuation line was parsed as a route: %+v", r)
		}
	}
}

// Captured `netstat -rn` output from macOS with Wi-Fi and a VPN tunnel.
const netstatSample = `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
127                127.0.0.1          UCS            lo0
127.0.0.1          127.0.0.1          UH             lo0
192.168.1          link#4             UCS            en0      !
192.168.1.1/32     link#4             UCS            en0      !
224.0.0/4          link#4             UmCS           en0      !

Internet6:
Destination                             Gateway                    Flags     Netif Expire
default                                 fe80::%utun0               UGcI      utun0
::1                                     ::1                        UHL         lo0
fe80::/64                               link#4                     UCI         en0
`

func TestParseNetstatRoutes(t *testing.T) {
	got := parseNetstatRoutes(netstatSample)
	if len(got) == 0 {
		t.Fatal("parsed no routes from the netstat sample")
	}

	byDest := make(map[string]Route, len(got))
	for _, r := range got {
		byDest[r.Family+" "+r.Destination] = r
	}

	v4def, ok := byDest["ipv4 0.0.0.0/0"]
	if !ok {
		t.Fatalf("no IPv4 default route: %+v", got)
	}
	if v4def.Gateway != "192.168.1.1" || v4def.Interface != "en0" {
		t.Errorf("IPv4 default = %+v, want gateway 192.168.1.1 on en0", v4def)
	}

	// The Internet6 header must switch the family for everything after it.
	v6def, ok := byDest["ipv6 ::/0"]
	if !ok {
		t.Fatalf("no IPv6 default route — the Internet6 header did not switch "+
			"the address family: %+v", got)
	}
	if v6def.Interface != "utun0" {
		t.Errorf("IPv6 default interface = %q, want utun0", v6def.Interface)
	}

	// netstat states no provenance, so Source must stay empty rather than being
	// guessed from the flags column.
	for _, r := range got {
		if r.Source != "" {
			t.Errorf("route %+v claims source %q, but netstat reports none", r, r.Source)
		}
	}
}

// TestParseNetstatExpandsAbbreviatedNetworks covers netstat's shorthand, where
// trailing zero octets are omitted and the octet count implies the prefix.
func TestParseNetstatExpandsAbbreviatedNetworks(t *testing.T) {
	cases := map[string]string{
		"127":         "127.0.0.0/8",
		"192.168.1":   "192.168.1.0/24",
		"10.4":        "10.4.0.0/16",
		"192.168.1.1": "192.168.1.1/32",
	}
	for in, want := range cases {
		if got := normalizeDestination(in, FamilyIPv4); got != want {
			t.Errorf("normalizeDestination(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeBSDGatewayDropsOnLinkMarkers pins that "link#4" and a bare MAC
// are reported as no gateway — neither is an address a consumer could route on.
func TestNormalizeBSDGatewayDropsOnLinkMarkers(t *testing.T) {
	for _, in := range []string{"link#4", "0:1c:42:3f:aa:bb", ""} {
		if got := normalizeBSDGateway(in); got != "" {
			t.Errorf("normalizeBSDGateway(%q) = %q, want empty", in, got)
		}
	}
	if got := normalizeBSDGateway("192.168.1.1"); got != "192.168.1.1" {
		t.Errorf("a real gateway was dropped: %q", got)
	}
}

// TestNormalizeWindowsNextHop pins that Windows's unspecified-address
// placeholder for an on-link route becomes an empty gateway.
func TestNormalizeWindowsNextHop(t *testing.T) {
	for _, in := range []string{"0.0.0.0", "::", "", "  "} {
		if got := normalizeWindowsNextHop(in); got != "" {
			t.Errorf("normalizeWindowsNextHop(%q) = %q, want empty", in, got)
		}
	}
	if got := normalizeWindowsNextHop("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("a real next hop was dropped: %q", got)
	}
}

func TestWindowsRouteProtocol(t *testing.T) {
	cases := map[uint16]string{
		2:  "local",
		3:  "static",
		19: "dhcp",
		14: "bgp",
		1:  "", // Other — unstated rather than invented
		99: "",
	}
	for in, want := range cases {
		if got := windowsRouteProtocol(in); got != want {
			t.Errorf("windowsRouteProtocol(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestWindowsAddressFamily(t *testing.T) {
	if got := windowsAddressFamily(2); got != FamilyIPv4 {
		t.Errorf("AF_INET mapped to %q, want %q", got, FamilyIPv4)
	}
	if got := windowsAddressFamily(23); got != FamilyIPv6 {
		t.Errorf("AF_INET6 mapped to %q, want %q", got, FamilyIPv6)
	}
}

// TestNormalizeSourceRejectsUnknownTokens is the bounded-vocabulary guarantee:
// no unrecognised token from command output may reach the wire through Source.
func TestNormalizeSourceRejectsUnknownTokens(t *testing.T) {
	for _, in := range []string{"", "unknown", "proto-17", strings.Repeat("x", 500)} {
		if got := normalizeSource(in); got != "" {
			t.Errorf("normalizeSource(%q) = %q, want empty", in, got)
		}
	}
	if got := normalizeSource("KERNEL"); got != "kernel" {
		t.Errorf("normalizeSource is not case-insensitive: got %q", got)
	}
}
