//go:build windows

package network

import (
	"testing"
)

const netshInterfaceSpeed = `
Admin State:                    Enabled
State:                          Connected
Interface Type:                 Dedicated
Interface Name:                 Wi-Fi
Link Speed:                     1000 Mbps
`

const netshInterfaceSpeedGbps = `
Admin State:                    Enabled
State:                          Connected
Interface Type:                 Dedicated
Interface Name:                 Ethernet
Link Speed:                     1 Gbps
`

const netshIPConfig = `
Configuration for interface "Wi-Fi"
    DHCP enabled:                         Yes
    IP Address:                           192.168.1.42
    Subnet Prefix:                        192.168.1.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.1.1
    Gateway Metric:                       0
    InterfaceMetric:                      35
`

const netshDNS = `
Configuration for interface "Wi-Fi"
    DNS servers configured through DHCP:  8.8.8.8
                                          8.8.4.4
    Register with which suffix:           Primary only
`

const netshWlanInterfaces = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX200 160MHz
    GUID                   : abcd1234-0000-0000-0000-aabbccddeeff
    Physical address       : aa:bb:cc:dd:ee:ff
    State                  : connected
    SSID                   : MyHomeNetwork
    BSSID                  : 11:22:33:44:55:66
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 90%
    Profile                : MyHomeNetwork

    Hosted network status  : Not available
`

func TestParseSpeedMbps(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"mbps value", netshInterfaceSpeed, 1000},
		{"gbps value", netshInterfaceSpeedGbps, 1000},
		{"empty output", "", 0},
		{"no speed line", "Admin State: Enabled\nState: Connected\n", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSpeedMbps(tc.input); got != tc.want {
				t.Errorf("parseSpeedMbps() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseDefaultGateway(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"has gateway", netshIPConfig, "192.168.1.1"},
		{"empty output", "", ""},
		{"no gateway line", "IP Address: 10.0.0.1\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDefaultGateway(tc.input); got != tc.want {
				t.Errorf("parseDefaultGateway() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseDNSServers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"two servers", netshDNS, []string{"8.8.8.8", "8.8.4.4"}},
		{"empty output", "", nil},
		{"no IPs", "Register with which suffix: Primary only\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDNSServers(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseDNSServers() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("parseDNSServers()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSplitKV(t *testing.T) {
	tests := []struct {
		input   string
		wantKey string
		wantVal string
		wantNil bool
	}{
		{"Key : Value", "Key", "Value", false},
		{"SSID                   : MyNet", "SSID", "MyNet", false},
		{"no colon here", "", "", true},
		{": only value", "", "", true},
		{"Key :", "Key", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := splitKV(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Errorf("splitKV(%q) = %v, want nil", tc.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("splitKV(%q) = nil, want [%q, %q]", tc.input, tc.wantKey, tc.wantVal)
			}
			if got[0] != tc.wantKey {
				t.Errorf("key = %q, want %q", got[0], tc.wantKey)
			}
			if got[1] != tc.wantVal {
				t.Errorf("val = %q, want %q", got[1], tc.wantVal)
			}
		})
	}
}

func TestParseBand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"802.11ax", "5GHz"},
		{"802.11ac", "5GHz"},
		{"802.11n", "2.4GHz"},
		{"802.11g", "2.4GHz"},
		{"802.11b", "2.4GHz"},
		{"6GHz", "6GHz"},
		{"5GHz band", "5GHz"},
		{"2.4GHz band", "2.4GHz"},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := parseBand(tc.input); got != tc.want {
				t.Errorf("parseBand(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBandFromChannel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1", "2.4GHz"},
		{"6", "2.4GHz"},
		{"14", "2.4GHz"},
		{"36", "5GHz"},
		{"100", "5GHz"},
		{"177", "5GHz"},
		{"191", "6GHz"},
		{"abc", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := bandFromChannel(tc.input); got != tc.want {
				t.Errorf("bandFromChannel(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseWiFiInfo(t *testing.T) {
	t.Run("matching interface returns populated WiFiInfo", func(t *testing.T) {
		info := parseWiFiInfo(netshWlanInterfaces, "Wi-Fi")
		if info == nil {
			t.Fatal("expected non-nil WiFiInfo")
		}
		if info.SSID != "MyHomeNetwork" {
			t.Errorf("SSID = %q, want %q", info.SSID, "MyHomeNetwork")
		}
		if info.SignalStrength != -55 { // (90/2)-100 = -55
			t.Errorf("SignalStrength = %d, want -55", info.SignalStrength)
		}
		if info.FrequencyBand != "5GHz" { // channel 36
			t.Errorf("FrequencyBand = %q, want 5GHz", info.FrequencyBand)
		}
	})
	t.Run("non-matching interface returns nil", func(t *testing.T) {
		if got := parseWiFiInfo(netshWlanInterfaces, "Ethernet"); got != nil {
			t.Errorf("expected nil for non-WiFi adapter, got %+v", got)
		}
	})
	t.Run("empty output returns nil", func(t *testing.T) {
		if got := parseWiFiInfo("", "Wi-Fi"); got != nil {
			t.Errorf("expected nil for empty output, got %+v", got)
		}
	})
}

func TestGetAdapterType(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"Wi-Fi", "WiFi"},
		{"wi-fi 2", "WiFi"},
		{"Ethernet", "Ethernet"},
		{"Ethernet 2", "Ethernet"},
		{"Local Area Connection", "Ethernet"},
		{"Bluetooth Network Connection", "Bluetooth"},
		{"VPN Client", "VPN"},
		{"vEthernet (Default Switch)", "Virtual"},
		{"VMware Network Adapter VMnet1", "Virtual"},
		{"Loopback Pseudo-Interface 1", "Loopback"},
		{"OpenVPN TAP-Windows6", "VPN"},
		{"Some Unknown Adapter", "Other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := getAdapterType(tc.name); got != tc.want {
				t.Errorf("getAdapterType(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"8.8.8.8", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"", false},
		{"not an ip", false},
		{"has spaces 1.2.3.4", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := isIPAddress(tc.input); got != tc.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetAdapterType_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	adapters := Get()
	for _, a := range adapters {
		if a.AdapterType == "" {
			t.Errorf("adapter %q has empty AdapterType", a.InterfaceName)
		}
	}
}
