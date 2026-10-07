//go:build linux

package network

// Fuzz target for the Linux network parsers (ip route, /etc/resolv.conf,
// iw dev <if> link). Gateways and DNS servers end up in the heartbeat payload,
// so anything returned must be a real IP address.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Linux).
// To fuzz: go test -run='^$' -fuzz='^FuzzLinuxNetworkParsers$' -fuzztime=1m ./internal/osinfo/network/

import (
	"net/netip"
	"testing"
)

func FuzzLinuxNetworkParsers(f *testing.F) {
	for _, s := range []string{
		ipRouteOutput, ipRouteNoDefault, resolvConf, resolvConfEmpty,
		iwLinkConnected, iwLinkDisconnected, iwLink24GHz,
		"default via", "default via dev eth0", "default via fe80::1%eth0 dev eth0",
		"nameserver", "nameserver not-an-ip", "nameservers 1.1.1.1", "nameserver 2001:db8::1",
		"SSID:", "signal:", "signal: -99999999999999999999 dBm", "freq:", "freq: abc", "",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, output string) {
		if gw := parseDefaultGatewayFromIPRoute(output); gw != "" {
			if _, err := netip.ParseAddr(gw); err != nil {
				t.Fatalf("gateway %q is not an IP address", gw)
			}
		}
		for _, s := range parseDNSServersFromResolvConf(output) {
			if _, err := netip.ParseAddr(s); err != nil {
				t.Fatalf("DNS server %q is not an IP address", s)
			}
		}
		if info := parseWiFiInfoFromIW(output); info != nil && info.SSID == "" {
			t.Fatal("parseWiFiInfoFromIW returned info with an empty SSID")
		}
	})
}

func TestParseResolvConf_RejectsMalformedEntries(t *testing.T) {
	got := parseDNSServersFromResolvConf("nameserver 1.1.1.1\nnameservers 9.9.9.9\nnameserver not-an-ip\nnameserver fe80::1%eth0\n")
	want := []string{"1.1.1.1", "fe80::1%eth0"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("parseDNSServersFromResolvConf() = %v, want %v", got, want)
	}
	if gw := parseDefaultGatewayFromIPRoute("default via dev eth0\n"); gw != "" {
		t.Fatalf("parseDefaultGatewayFromIPRoute(no address) = %q, want empty", gw)
	}
}
