//go:build darwin

package network

import (
	"testing"
)

const networksetupHardwarePorts = `
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Thunderbolt Ethernet Slot 1
Device: en1
Ethernet Address: 11:22:33:44:55:00

Hardware Port: Bluetooth PAN
Device: en3
Ethernet Address: aa:bb:cc:00:11:22

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:00:00:00:00:00
`

const networksetupInfo = `
Manual Configuration
IP address: 192.168.1.42
Subnet mask: 255.255.255.0
Router: 192.168.1.1
Link Speed: 1000 Mbps
`

const networksetupInfoGbps = `
Manual Configuration
IP address: 10.0.0.5
Subnet mask: 255.255.0.0
Router: 10.0.0.1
Link Speed: 1 Gbps
`

const netstatOutput = `
Routing tables

Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
default            192.168.1.1        UGScg           0       12      en0
127                127.0.0.1          UCS             0        0      lo0
192.168.1          link#5             UCS             0        0      en0
`

const airportOutput = `
     agrCtlRSSI: -62
     agrExtRSSI: 0
    agrCtlNoise: -95
    agrExtNoise: 0
          state: running
        op mode: station
     lastTxRate: 390
        maxRate: 390
lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: aa:bb:cc:dd:ee:ff
           SSID: MyHomeNetwork
            MCS: 8
        channel: 36,80
`

const airportOutput24 = `
     agrCtlRSSI: -71
          state: running
          BSSID: 11:22:33:44:55:66
           SSID: Office2G
        channel: 6
`

const dnsOutput = `
8.8.8.8
8.8.4.4
`

const dnsOutputNone = `
There aren't any DNS Servers set on Wi-Fi.
`

func TestParseHardwarePorts(t *testing.T) {
	friendly, services := parseHardwarePorts(networksetupHardwarePorts)

	cases := []struct {
		dev      string
		wantName string
	}{
		{"en0", "Wi-Fi"},
		{"en1", "Thunderbolt Ethernet Slot 1"},
		{"en3", "Bluetooth PAN"},
	}
	for _, c := range cases {
		if got := friendly[c.dev]; got != c.wantName {
			t.Errorf("friendly[%q] = %q, want %q", c.dev, got, c.wantName)
		}
		if got := services[c.dev]; got != c.wantName {
			t.Errorf("services[%q] = %q, want %q", c.dev, got, c.wantName)
		}
	}
	if _, ok := friendly["bridge0"]; !ok {
		t.Error("expected bridge0 to be present in friendly map")
	}
}

func TestParseHardwarePorts_Empty(t *testing.T) {
	friendly, services := parseHardwarePorts("")
	if len(friendly) != 0 {
		t.Errorf("expected empty map, got %v", friendly)
	}
	if len(services) != 0 {
		t.Errorf("expected empty map, got %v", services)
	}
}

func TestParseSpeedMbpsFromNetworksetup(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"Mbps", networksetupInfo, 1000},
		{"Gbps", networksetupInfoGbps, 1000},
		{"no speed line", "IP address: 1.2.3.4\n", 0},
		{"empty", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSpeedMbpsFromNetworksetup(tc.input); got != tc.want {
				t.Errorf("parseSpeedMbpsFromNetworksetup() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseDefaultGatewayFromNetstat(t *testing.T) {
	tests := []struct {
		name      string
		ifaceName string
		want      string
	}{
		{"en0 gateway found", "en0", "192.168.1.1"},
		{"en1 not in table", "en1", ""},
		{"empty output", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDefaultGatewayFromNetstat(netstatOutput, tc.ifaceName)
			if got != tc.want {
				t.Errorf("parseDefaultGatewayFromNetstat(iface=%q) = %q, want %q", tc.ifaceName, got, tc.want)
			}
		})
	}
}

func TestParseDNSServersOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"two servers", dnsOutput, []string{"8.8.8.8", "8.8.4.4"}},
		{"none configured", dnsOutputNone, nil},
		{"empty", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDNSServersOutput(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseDNSServersOutput() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseAirportInfo(t *testing.T) {
	t.Run("5GHz connected", func(t *testing.T) {
		info := parseAirportInfo(airportOutput)
		if info == nil {
			t.Fatal("expected non-nil WiFiInfo")
		}
		if info.SSID != "MyHomeNetwork" {
			t.Errorf("SSID = %q, want %q", info.SSID, "MyHomeNetwork")
		}
		if info.SignalStrength != -62 {
			t.Errorf("SignalStrength = %d, want -62", info.SignalStrength)
		}
		if info.FrequencyBand != "5GHz" {
			t.Errorf("FrequencyBand = %q, want 5GHz", info.FrequencyBand)
		}
	})
	t.Run("2.4GHz connected", func(t *testing.T) {
		info := parseAirportInfo(airportOutput24)
		if info == nil {
			t.Fatal("expected non-nil WiFiInfo")
		}
		if info.FrequencyBand != "2.4GHz" {
			t.Errorf("FrequencyBand = %q, want 2.4GHz", info.FrequencyBand)
		}
	})
	t.Run("empty output returns nil", func(t *testing.T) {
		if got := parseAirportInfo(""); got != nil {
			t.Errorf("expected nil for empty output, got %+v", got)
		}
	})
}

func TestBandFromChannel(t *testing.T) {
	tests := []struct {
		ch   int
		want string
	}{
		{1, "2.4GHz"},
		{6, "2.4GHz"},
		{14, "2.4GHz"},
		{36, "5GHz"},
		{100, "5GHz"},
		{177, "5GHz"},
		{191, "6GHz"},
		{0, ""},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			if got := bandFromChannel(tc.ch); got != tc.want {
				t.Errorf("bandFromChannel(%d) = %q, want %q", tc.ch, got, tc.want)
			}
		})
	}
}

func TestGet_Darwin_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network adapter collection in -short mode")
	}
	adapters := Get()
	for i, a := range adapters {
		t.Logf("adapter[%d]: name=%s friendly=%s type=%s status=%s connected=%v gw=%s dns=%v wifi=%v",
			i, a.InterfaceName, a.FriendlyName, a.AdapterType, a.Status, a.IsConnected,
			a.DefaultGateway, a.DNSServers, a.WiFi)
		if a.AdapterType == "" {
			t.Errorf("adapter[%d] %s: AdapterType is empty", i, a.InterfaceName)
		}
	}
}
