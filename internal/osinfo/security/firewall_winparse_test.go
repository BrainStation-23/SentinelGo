package security

import (
	"net/netip"
	"slices"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// winFwFixture is probe output from a workstation on a Public network, with
// the firewall on and blocking inbound by default. It has the stock "File and
// Printer Sharing (SMB-In)" rule for Domain and Private, an RDP rule for
// every profile, and keyword-port and ICMP rules that must never match.
const winFwFixture = `{
 "rules": [
  {"id": "FPS-SMB-In-TCP", "action": "Allow", "profile": 3},
  {"id": "RemoteDesktop-UserMode-In-TCP", "action": "Allow", "profile": 0},
  {"id": "RPCSS-In", "action": "Allow", "profile": 0},
  {"id": "ICMP4-In", "action": "Allow", "profile": 0},
  {"id": "VNC-Range", "action": "Allow", "profile": 4},
  {"id": "Block-VNC-5901", "action": "Block", "profile": 0}
 ],
 "ports": [
  {"id": "FPS-SMB-In-TCP", "protocol": "TCP", "local_port": "445"},
  {"id": "RemoteDesktop-UserMode-In-TCP", "protocol": "TCP", "local_port": "3389"},
  {"id": "RPCSS-In", "protocol": "TCP", "local_port": "RPCEPMap"},
  {"id": "ICMP4-In", "protocol": "ICMPv4", "local_port": "RPC"},
  {"id": "VNC-Range", "protocol": "TCP", "local_port": "5800,5900-5906"},
  {"id": "Block-VNC-5901", "protocol": "6", "local_port": "5901"}
 ],
 "apps": [
  {"id": "FPS-SMB-In-TCP", "program": "System"},
  {"id": "RemoteDesktop-UserMode-In-TCP", "program": "%SystemRoot%\\system32\\svchost.exe"},
  {"id": "RPCSS-In", "program": "%systemroot%\\system32\\svchost.exe"},
  {"id": "ICMP4-In", "program": "System"},
  {"id": "VNC-Range", "program": "Any"},
  {"id": "Block-VNC-5901", "program": "Any"}
 ],
 "profiles": [
  {"name": "Domain", "enabled": true, "default_inbound": "Block"},
  {"name": "Private", "enabled": true, "default_inbound": "NotConfigured"},
  {"name": "Public", "enabled": true, "default_inbound": "Block"}
 ],
 "networks": [{"interface": "Ethernet", "category": "Public"}]
}`

func mustWinFirewall(t *testing.T) winFirewall {
	t.Helper()
	fw, ok := parseWinFirewall(winFwFixture)
	if !ok {
		t.Fatal("parseWinFirewall(fixture) failed")
	}
	return fw
}

func TestWinFirewall_Check(t *testing.T) {
	tests := []struct {
		name     string
		networks []winFwNetwork // nil = the fixture's Public network
		port     shared.ListeningPort
		verdict  string
		profiles []string
	}{
		{
			name:    "SMB rule covers Domain and Private only",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"},
			verdict: firewallBlocked,
		},
		{
			name:     "SMB on a Private network",
			networks: []winFwNetwork{{Interface: "Wi-Fi", Category: "Private"}},
			port:     shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"},
			verdict:  firewallAllowed, profiles: []string{"Private"},
		},
		{
			name:     "domain network uses the Domain profile",
			networks: []winFwNetwork{{Interface: "Ethernet", Category: "DomainAuthenticated"}, {Interface: "VPN", Category: "Public"}},
			port:     shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"},
			verdict:  firewallAllowed, profiles: []string{"Domain"},
		},
		{
			name:     "no connected network checks every profile",
			networks: []winFwNetwork{},
			port:     shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"},
			verdict:  firewallAllowed, profiles: []string{"Domain", "Private"},
		},
		{
			name:    "RDP rule for any profile, svchost listener",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 3389, ProcessName: "svchost.exe"},
			verdict: firewallAllowed, profiles: []string{"Public"},
		},
		{
			name:    "program filter doesn't match another process",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 3389, ProcessName: "xrdp"},
			verdict: firewallBlocked,
		},
		{
			name:    "unknown process matches any program filter",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 3389},
			verdict: firewallAllowed, profiles: []string{"Public"},
		},
		{
			name:    "protocol mismatch",
			port:    shared.ListeningPort{Protocol: "udp", Port: 3389, ProcessName: "svchost.exe"},
			verdict: firewallBlocked,
		},
		{
			name:    "port in a range",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 5903, ProcessName: "vncserver"},
			verdict: firewallAllowed, profiles: []string{"Public"},
		},
		{
			name:    "block rule wins over allow",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 5901, ProcessName: "vncserver"},
			verdict: firewallBlocked,
		},
		{
			name:    "keyword ports and ICMP rules don't match",
			port:    shared.ListeningPort{Protocol: "tcp", Port: 135, ProcessName: "svchost.exe"},
			verdict: firewallBlocked,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := mustWinFirewall(t)
			if tt.networks != nil {
				fw.Networks = tt.networks
			}
			verdict, profiles := fw.checker(nil)(tt.port)
			if verdict != tt.verdict || !slices.Equal(profiles, tt.profiles) {
				t.Errorf("check = %q, %q; want %q, %q", verdict, profiles, tt.verdict, tt.profiles)
			}
		})
	}
}

func TestWinFirewall_ProfileDisabled(t *testing.T) {
	fw := mustWinFirewall(t)
	fw.Profiles[2].Enabled = false // Public
	verdict, profiles := fw.checker(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"})
	if verdict != firewallDisabled || !slices.Equal(profiles, []string{"Public"}) {
		t.Errorf("check = %q, %q; want disabled on Public", verdict, profiles)
	}
}

func TestWinFirewall_DefaultInboundAllow(t *testing.T) {
	fw := mustWinFirewall(t)
	fw.Profiles[2].DefaultInbound = "Allow"
	if verdict, _ := fw.checker(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"}); verdict != firewallAllowed {
		t.Errorf("verdict = %q, want allowed", verdict)
	}
}

func TestWinFirewall_MissingProfileIsUnknown(t *testing.T) {
	fw := mustWinFirewall(t)
	fw.Profiles = fw.Profiles[:2] // no Public state
	if verdict, _ := fw.checker(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445}); verdict != firewallUnknown {
		t.Errorf("verdict = %q, want unknown", verdict)
	}
}

func TestParseWinFirewall_Unusable(t *testing.T) {
	for _, out := range []string{"", "not json", `{"rules": []}`} {
		if _, ok := parseWinFirewall(out); ok {
			t.Errorf("parseWinFirewall(%q) ok, want false", out)
		}
	}
}

func TestWinFirewall_NetworkProfiles(t *testing.T) {
	fw := winFirewall{Networks: []winFwNetwork{
		{Interface: "Ethernet", Category: "DomainAuthenticated"},
		{Interface: "Wi-Fi", Category: "Private"},
		{Interface: "Odd", Category: "Unknown"},
	}}
	got := fw.networkProfiles()
	want := []shared.NetworkFirewallProfile{{Interface: "Ethernet", Profile: "Domain"}, {Interface: "Wi-Fi", Profile: "Private"}}
	if !slices.Equal(got, want) {
		t.Errorf("networkProfiles = %+v, want %+v", got, want)
	}
}

// TestWinFirewall_MissingFilterIsUnknown: a rule whose port or program
// filter the probe didn't return must not act as "any port"/"any program".
func TestWinFirewall_MissingFilterIsUnknown(t *testing.T) {
	smb := shared.ListeningPort{Protocol: "tcp", Port: 445, ProcessName: "System"}
	fw := mustWinFirewall(t)
	fw.Ports = fw.Ports[1:] // FPS-SMB-In-TCP's port filter is missing
	if got, _ := fw.checker(nil)(smb); got != firewallUnknown {
		t.Errorf("missing port filter: %q, want unknown", got)
	}
	fw = mustWinFirewall(t)
	fw.Apps = fw.Apps[1:]
	if got, _ := fw.checker(nil)(smb); got != firewallUnknown {
		t.Errorf("missing program filter: %q, want unknown", got)
	}
}

// TestWinFirewall_InterfaceProfile: a socket bound to one interface is
// governed by that network's profile only; a wildcard socket by every
// connected network's.
func TestWinFirewall_InterfaceProfile(t *testing.T) {
	fw := mustWinFirewall(t)
	fw.Networks = []winFwNetwork{
		{Interface: "Wi-Fi", Index: 7, Category: "Public"},
		{Interface: "Ethernet", Index: 3, Category: "Private"},
	}
	ifaceIndex := func(a netip.Addr) (int, bool) {
		switch a.String() {
		case "192.168.1.20":
			return 7, true // Wi-Fi
		case "10.0.0.20":
			return 3, true // Ethernet
		case "172.20.0.1":
			return 9, true // no network profile (e.g. a virtual switch)
		}
		return 0, false
	}
	check := fw.checker(ifaceIndex)
	tests := []struct {
		addr     string
		verdict  string
		profiles []string
	}{
		{"192.168.1.20", firewallBlocked, nil},                 // Public blocks SMB
		{"10.0.0.20", firewallAllowed, []string{"Private"}},    // Private allows it
		{"0.0.0.0", firewallAllowed, []string{"Private"}},      // wildcard: every network
		{"172.20.0.1", firewallAllowed, []string{"Private"}},   // no profile: every network
		{"192.168.99.9", firewallAllowed, []string{"Private"}}, // interface not found
	}
	for _, tt := range tests {
		verdict, profiles := check(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: tt.addr, ProcessName: "System"})
		if verdict != tt.verdict || !slices.Equal(profiles, tt.profiles) {
			t.Errorf("%s: %q, %q; want %q, %q", tt.addr, verdict, profiles, tt.verdict, tt.profiles)
		}
	}
}
