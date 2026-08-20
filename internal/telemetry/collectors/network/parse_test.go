package network

import "testing"

func TestIsVPNInterfaceName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"tun0", true}, {"tap0", true}, {"wg0", true}, {"utun3", true},
		{"ppp0", true}, {"ipsec0", true},
		{"eth0", false}, {"en0", false}, {"Wi-Fi", false}, {"Ethernet", false},
	}
	for _, tc := range tests {
		if got := isVPNInterfaceName(tc.name); got != tc.want {
			t.Errorf("isVPNInterfaceName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseWindowsInterfaces_Array(t *testing.T) {
	const sample = `[{"Name":"Ethernet","Mtu":1500,"Dhcp":"Enabled","Virtual":false}]`
	rows, err := parseWindowsInterfaces(sample)
	if err != nil {
		t.Fatalf("parseWindowsInterfaces: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	e := rows[0].toExtra()
	if e.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", e.MTU)
	}
	if e.IsPhysical == nil || !*e.IsPhysical {
		t.Errorf("IsPhysical = %v, want true", e.IsPhysical)
	}
	if e.DHCPEnabled == nil || !*e.DHCPEnabled {
		t.Errorf("DHCPEnabled = %v, want true", e.DHCPEnabled)
	}
}

func TestParseWindowsInterfaces_SingleObject(t *testing.T) {
	const sample = `{"Name":"vEthernet","Mtu":1500,"Dhcp":"Disabled","Virtual":true}`
	rows, err := parseWindowsInterfaces(sample)
	if err != nil {
		t.Fatalf("parseWindowsInterfaces: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %+v", rows)
	}
	e := rows[0].toExtra()
	if e.IsPhysical == nil || *e.IsPhysical {
		t.Errorf("IsPhysical = %v, want false (Virtual=true)", e.IsPhysical)
	}
	if e.DHCPEnabled == nil || *e.DHCPEnabled {
		t.Errorf("DHCPEnabled = %v, want false", e.DHCPEnabled)
	}
}

func TestParseWindowsInterfaces_UnknownDHCP(t *testing.T) {
	const sample = `{"Name":"Loopback","Mtu":0,"Dhcp":"","Virtual":true}`
	rows, err := parseWindowsInterfaces(sample)
	if err != nil {
		t.Fatalf("parseWindowsInterfaces: %v", err)
	}
	e := rows[0].toExtra()
	if e.DHCPEnabled != nil {
		t.Errorf("DHCPEnabled = %v, want nil for an unrecognised Dhcp value", *e.DHCPEnabled)
	}
}

func TestParseNmcliDHCP(t *testing.T) {
	tests := []struct {
		in        string
		wantNil   bool
		wantValue bool
	}{
		{"yes\n", false, true},
		{"no\n", false, false},
		{"", true, false},
		{"unexpected\n", true, false},
	}
	for _, tc := range tests {
		got := parseNmcliDHCP(tc.in)
		if tc.wantNil {
			if got != nil {
				t.Errorf("parseNmcliDHCP(%q) = %v, want nil", tc.in, *got)
			}
			continue
		}
		if got == nil || *got != tc.wantValue {
			t.Errorf("parseNmcliDHCP(%q) = %v, want %v", tc.in, got, tc.wantValue)
		}
	}
}

func TestParseIfconfigMTU(t *testing.T) {
	const sample = `en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6467<RXCSUM,TXCSUM,TSO4,TSO6,CHANNEL_IO>
	ether ac:de:48:00:11:22
	inet6 fe80::1%en0 prefixlen 64 scopeid 0x4
	inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
`
	if got := parseIfconfigMTU(sample); got != 1500 {
		t.Errorf("parseIfconfigMTU() = %d, want 1500", got)
	}
}

func TestParseIfconfigMTU_Missing(t *testing.T) {
	if got := parseIfconfigMTU("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>\n"); got != 0 {
		t.Errorf("parseIfconfigMTU() = %d, want 0", got)
	}
}

func TestClassifyDarwinInterface(t *testing.T) {
	tests := []struct {
		name    string
		wantNil bool
		want    bool
	}{
		{"en0", false, true},
		{"en5", false, true},
		{"lo0", false, false},
		{"utun3", false, false},
		{"bridge100", false, false},
		{"awdl0", false, false},
		{"gif0", false, false},
		{"somethingelse7", true, false},
	}
	for _, tc := range tests {
		got := classifyDarwinInterface(tc.name)
		if tc.wantNil {
			if got != nil {
				t.Errorf("classifyDarwinInterface(%q) = %v, want nil", tc.name, *got)
			}
			continue
		}
		if got == nil || *got != tc.want {
			t.Errorf("classifyDarwinInterface(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseScutilProxy_Enabled(t *testing.T) {
	const sample = `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example.com
  HTTPSEnable : 1
}
`
	enabled, server := parseScutilProxy(sample)
	if enabled == nil || !*enabled {
		t.Errorf("enabled = %v, want true", enabled)
	}
	if server != "proxy.example.com:8080" {
		t.Errorf("server = %q, want proxy.example.com:8080", server)
	}
}

func TestParseScutilProxy_Disabled(t *testing.T) {
	const sample = `<dictionary> {
  HTTPEnable : 0
}
`
	enabled, server := parseScutilProxy(sample)
	if enabled == nil || *enabled {
		t.Errorf("enabled = %v, want false", enabled)
	}
	if server != "" {
		t.Errorf("server = %q, want empty", server)
	}
}
