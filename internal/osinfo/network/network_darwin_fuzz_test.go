//go:build darwin

package network

// Fuzz target for the macOS network parsers (networksetup, netstat, airport).
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (macOS).
// To fuzz: go test -run='^$' -fuzz='^FuzzDarwinNetworkParsers$' -fuzztime=1m ./internal/osinfo/network/

import "testing"

func FuzzDarwinNetworkParsers(f *testing.F) {
	for _, s := range []string{
		networksetupHardwarePorts, networksetupInfo, networksetupInfoGbps, netstatOutput,
		airportOutput, airportOutput24, dnsOutput, dnsOutputNone,
		"Link Speed: -5 Mbps", "Link Speed: 9223372036854775807 Gbps",
		"default link#17 UCSIg 0 0 en0", "agrCtlRSSI: -9999", "channel: ,", "SSID:",
		"Hardware Port:\nDevice:", "", "\n",
	} {
		f.Add(s, "en0")
	}

	f.Fuzz(func(t *testing.T, output, iface string) {
		_, _ = parseHardwarePorts(output)
		if n := parseSpeedMbpsFromNetworksetup(output); n < 0 {
			t.Fatalf("parseSpeedMbpsFromNetworksetup = %d, want >= 0", n)
		}
		if gw := parseDefaultGatewayFromNetstat(output, iface); gw != "" && !isIPAddress(gw) {
			t.Fatalf("gateway %q is not an IP address", gw)
		}
		for _, s := range parseDNSServersOutput(output) {
			if !isIPAddress(s) {
				t.Fatalf("DNS server %q is not an IP address", s)
			}
		}
		if info := parseAirportInfo(output); info != nil {
			if info.SSID == "" {
				t.Fatal("parseAirportInfo returned info with an empty SSID")
			}
			if info.SignalStrength < -127 || info.SignalStrength > 0 {
				t.Fatalf("SignalStrength = %d dBm, want -127..0", info.SignalStrength)
			}
		}
	})
}
