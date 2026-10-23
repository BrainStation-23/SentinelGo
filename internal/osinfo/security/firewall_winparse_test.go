package security

import (
	"fmt"
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
 "addrs": [
  {"id": "FPS-SMB-In-TCP", "local_address": "Any", "remote_address": "LocalSubnet"},
  {"id": "RemoteDesktop-UserMode-In-TCP", "local_address": "Any", "remote_address": "Any"},
  {"id": "RPCSS-In", "local_address": "Any", "remote_address": "Any"},
  {"id": "ICMP4-In", "local_address": "Any", "remote_address": "Any"},
  {"id": "VNC-Range", "local_address": "Any", "remote_address": "Any"},
  {"id": "Block-VNC-5901", "local_address": "Any", "remote_address": "Any"}
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
	fw = mustWinFirewall(t)
	fw.Addrs = fw.Addrs[1:]
	if got, _ := fw.checker(nil)(smb); got != firewallUnknown {
		t.Errorf("missing address filter: %q, want unknown", got)
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

// TestWinFirewall_BlockAllInbound: "block all incoming connections" makes
// the profile ignore its allow rules (Devin's example: an SSH allow rule on
// Public).
func TestWinFirewall_BlockAllInbound(t *testing.T) {
	rdp := shared.ListeningPort{Protocol: "tcp", Port: 3389, ProcessName: "svchost.exe"}
	fw := mustWinFirewall(t)
	fw.Profiles[2].BlockAllInbound = true // Public
	if got, _ := fw.checker(nil)(rdp); got != firewallBlocked {
		t.Errorf("block all: %q, want blocked", got)
	}
	fw.Profiles[2].DefaultInbound = "Allow"
	if got, _ := fw.checker(nil)(rdp); got != firewallAllowed {
		t.Errorf("block all, default allow: %q, want allowed", got)
	}
}

// TestWinFirewall_AddressScopes: an allow rule for one local address doesn't
// reach a socket bound to another, and a block rule decides only when it
// covers every connection: any remote address, the socket's address, and
// the listener's program.
func TestWinFirewall_AddressScopes(t *testing.T) {
	const smbRules = `{"rules":[{"id":"allow","action":"Allow","profile":0},{"id":"block","action":"Block","profile":0}],` +
		`"ports":[{"id":"allow","protocol":"TCP","local_port":"445"},{"id":"block","protocol":"TCP","local_port":"445"}],` +
		`"apps":[{"id":"allow","program":"Any"},{"id":"block","program":"%s"}],` +
		`"addrs":[{"id":"allow","local_address":"%s","remote_address":"Any"},{"id":"block","local_address":"%s","remote_address":"%s"}],` +
		`"profiles":[{"name":"Public","enabled":true,"default_inbound":"Block"}],"networks":[{"interface":"Ethernet","category":"Public"}]}`
	tests := []struct {
		name                                 string
		blockProgram, allowLocal, blockLocal string
		blockRemote, addr, process           string
		want                                 string
	}{
		{"allow for another local address", "Any", "10.0.0.5", "127.0.0.1", "Any", "192.168.1.20", "System", firewallBlocked},
		{"allow for the socket's address", "Any", "10.0.0.5", "127.0.0.1", "Any", "10.0.0.5", "System", firewallAllowed},
		{"allow for a subnet in mask form", "Any", "10.0.0.0/255.255.255.0", "127.0.0.1", "Any", "10.0.0.5", "System", firewallAllowed},
		{"allow for a range", "Any", "10.0.0.1-10.0.0.9", "127.0.0.1", "Any", "10.0.0.5", "System", firewallAllowed},
		{"allow keyword can't be evaluated", "Any", "LocalSubnet", "127.0.0.1", "Any", "192.168.1.20", "System", firewallAllowed},
		{"allow for one address, wildcard socket", "Any", "10.0.0.5", "127.0.0.1", "Any", "0.0.0.0", "System", firewallAllowed},
		{"block from everywhere wins", "Any", "Any", "Any", "Any", "0.0.0.0", "System", firewallBlocked},
		{"block from one subnet doesn't decide", "Any", "Any", "Any", "10.0.0.0/8", "0.0.0.0", "System", firewallAllowed},
		{"block on the socket's address", "Any", "Any", "10.0.0.5", "Any", "10.0.0.5", "System", firewallBlocked},
		{"block on one address, wildcard socket", "Any", "Any", "10.0.0.5", "Any", "0.0.0.0", "System", firewallAllowed},
		{"program block, matching process", "System", "Any", "Any", "Any", "0.0.0.0", "System", firewallBlocked},
		{"program block, unknown process", "System", "Any", "Any", "Any", "0.0.0.0", "", firewallAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw, ok := parseWinFirewall(fmt.Sprintf(smbRules, tt.blockProgram, tt.allowLocal, tt.blockLocal, tt.blockRemote))
			if !ok {
				t.Fatal("parseWinFirewall failed")
			}
			if got, _ := fw.checker(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: tt.addr, ProcessName: tt.process}); got != tt.want {
				t.Errorf("verdict = %q, want %q", got, tt.want)
			}
		})
	}
}
