//go:build windows

package network

// Fuzz target for the Windows network parsers (netsh interface / wlan output).
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Windows).
// To fuzz: go test -run='^$' -fuzz='^FuzzWindowsNetworkParsers$' -fuzztime=1m ./internal/osinfo/network/

import (
	"strings"
	"testing"
)

func FuzzWindowsNetworkParsers(f *testing.F) {
	for _, s := range []string{
		netshInterfaceSpeed, netshInterfaceSpeedGbps, netshIPConfig, netshDNS, netshWlanInterfaces,
		"Speed: -5 Mbps", "Speed: 9223372036854775807 Gbps", "Speed:", "Default Gateway: None",
		"Default Gateway: not-an-ip", "Signal : 99999999%", "Signal : -5%", "Channel : -3",
		"SSID : ", ":", "", "\n\n\n",
	} {
		f.Add(s, "Wi-Fi")
	}
	f.Add(netshWlanInterfaces, "")

	f.Fuzz(func(t *testing.T, output, iface string) {
		if n := parseSpeedMbps(output); n < 0 {
			t.Fatalf("parseSpeedMbps = %d, want >= 0", n)
		}
		if gw := parseDefaultGateway(output); gw != "" && !isIPAddress(gw) {
			t.Fatalf("gateway %q is not an IP address", gw)
		}
		for _, s := range parseDNSServers(output) {
			if !isIPAddress(s) {
				t.Fatalf("DNS server %q is not an IP address", s)
			}
		}
		_ = parseDeviceName(output)
		if info := parseWiFiInfo(output, iface); info != nil {
			if info.SSID == "" {
				t.Fatal("parseWiFiInfo returned info with an empty SSID")
			}
			if info.SignalStrength < -100 || info.SignalStrength > 0 {
				t.Fatalf("SignalStrength = %d dBm, want -100..0", info.SignalStrength)
			}
		}
		for _, line := range strings.Split(output, "\n") {
			if kv := splitKV(line); kv != nil && (len(kv) != 2 || kv[0] == "") {
				t.Fatalf("splitKV(%q) = %q", line, kv)
			}
			_ = parseBand(line)
		}
	})
}
