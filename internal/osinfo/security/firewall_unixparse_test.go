package security

import (
	"fmt"
	"net/netip"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

const ufwVerboseFixture = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW IN    Anywhere
5432/tcp                   DENY IN     10.9.9.9
5432/tcp                   ALLOW IN    192.168.1.0/24
3306                       DENY IN     Anywhere
3306                       ALLOW IN    Anywhere
5900:5906/tcp              LIMIT IN    Anywhere
27017/tcp on eth1          ALLOW IN    Anywhere
10.0.0.5 6379/tcp          ALLOW IN    Anywhere
Samba Custom               ALLOW IN    Anywhere
445/tcp                    ALLOW OUT   Anywhere
OpenSSH (v6)               ALLOW IN    Anywhere (v6)
`

const ufwAppFixture = `[OpenSSH]
title=Secure shell server, an rshd replacement
description=OpenSSH is a free implementation of the Secure Shell protocol.
ports=22/tcp

[CIFS]
title=SMB/CIFS server
ports=137,138/udp|139,445/tcp
`

func TestUFW_Check(t *testing.T) {
	st := parseUFWStatus(ufwVerboseFixture)
	if !st.active || st.defaultIncoming != "deny" {
		t.Fatalf("status = %+v, want active with default deny", st)
	}
	check := st.check(parseUFWAppProfiles([]string{ufwAppFixture}), ufwHost{})

	tests := []struct {
		proto string
		port  uint16
		want  string
	}{
		{"tcp", 22, firewallAllowed},    // OpenSSH app profile
		{"tcp", 5432, firewallAllowed},  // deny from one source doesn't decide; allow from a subnet does
		{"tcp", 3306, firewallBlocked},  // first matching rule wins
		{"udp", 3306, firewallBlocked},  // no protocol = both
		{"tcp", 5903, firewallAllowed},  // LIMIT allows, rate-limited
		{"tcp", 27017, firewallAllowed}, // interface-scoped rule
		{"tcp", 6379, firewallAllowed},  // rule with a destination address
		{"tcp", 445, firewallUnknown},   // "Samba Custom" isn't an installed profile; OUT rule skipped
	}
	for _, tt := range tests {
		if got, _ := check(shared.ListeningPort{Protocol: tt.proto, Port: tt.port}); got != tt.want {
			t.Errorf("%s/%d = %q, want %q", tt.proto, tt.port, got, tt.want)
		}
	}
}

func TestUFW_DefaultAllowAndAllPorts(t *testing.T) {
	st := parseUFWStatus("Status: active\nDefault: allow (incoming), allow (outgoing)\n")
	if got, _ := st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
		t.Errorf("default allow: %q", got)
	}
	st = parseUFWStatus("Status: active\nDefault: reject (incoming)\n\nTo  Action  From\n--  ------  ----\nAnywhere                   ALLOW IN    10.0.0.0/8\n")
	if got, _ := st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
		t.Errorf("allow all ports from a subnet: %q", got)
	}
	if got, _ := parseUFWStatus("Status: active\nDefault: deny (incoming)\n").check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22}); got != firewallBlocked {
		t.Errorf("no rules, default deny: %q", got)
	}
	if parseUFWStatus("Status: inactive\n").active {
		t.Error("inactive parsed as active")
	}
}

func TestParseUFWAppProfiles(t *testing.T) {
	apps := parseUFWAppProfiles([]string{ufwAppFixture})
	cifs := apps["CIFS"]
	if len(cifs) != 4 || !anyCovers(cifs, shared.ListeningPort{Protocol: "udp", Port: 138}) || anyCovers(cifs, shared.ListeningPort{Protocol: "tcp", Port: 137}) {
		t.Errorf("CIFS = %+v", cifs)
	}
}

const firewalldFixture = `block
  target: %%REJECT%%
  interfaces:
  services:

dmz
  target: default
  services: ssh

public (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: dhcpv6-client ssh custom-db
  ports: 8080/tcp 5900-5906/tcp 161/udp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="10.0.0.0/8" port port="445" protocol="tcp" accept
	rule family="ipv4" source address="10.0.0.0/8" port port="139" protocol="tcp" reject
	rule family="ipv4" source address="10.1.0.0/16" service name="redis" accept

trusted
  target: ACCEPT
  interfaces:
`

func firewalldServices(name string) ([]portSpec, bool) {
	switch name {
	case "ssh":
		return []portSpec{{protocol: "tcp", from: 22, to: 22}}, true
	case "dhcpv6-client":
		return []portSpec{{protocol: "udp", from: 546, to: 546}}, true
	case "redis":
		return []portSpec{{protocol: "tcp", from: 6379, to: 6379}}, true
	}
	return nil, false
}

func TestFirewalld_Check(t *testing.T) {
	zones := parseFirewalldZones(firewalldFixture)
	if len(zones) != 4 {
		t.Fatalf("zones = %+v", zones)
	}
	check := firewalldCheck(zones, firewalldServices, nil)
	tests := []struct {
		proto string
		port  uint16
		want  string
	}{
		{"tcp", 22, firewallAllowed},   // service
		{"tcp", 5904, firewallAllowed}, // port range
		{"udp", 161, firewallAllowed},  // port, udp
		{"tcp", 445, firewallAllowed},  // rich rule accept
		{"tcp", 6379, firewallAllowed}, // rich rule service
		{"tcp", 3389, firewallUnknown}, // custom-db can't be resolved
	}
	for _, tt := range tests {
		if got, _ := check(shared.ListeningPort{Protocol: tt.proto, Port: tt.port}); got != tt.want {
			t.Errorf("%s/%d = %q, want %q", tt.proto, tt.port, got, tt.want)
		}
	}

	// With every service resolvable, an unopened port is blocked; the
	// inactive trusted zone (target ACCEPT) doesn't count.
	known := func(name string) ([]portSpec, bool) {
		specs, ok := firewalldServices(name)
		return specs, ok || name == "custom-db"
	}
	for _, port := range []uint16{3389, 139} {
		if got, _ := firewalldCheck(zones, known, nil)(shared.ListeningPort{Protocol: "tcp", Port: port}); got != firewallBlocked {
			t.Errorf("tcp/%d = %q, want blocked", port, got)
		}
	}
}

func TestFirewalld_DefaultZoneWhenNoneActive(t *testing.T) {
	zones := parseFirewalldZones("public (default)\n  target: default\n  services: ssh\ntrusted\n  target: ACCEPT\n")
	check := firewalldCheck(zones, firewalldServices, nil)
	if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: 22}); got != firewallAllowed {
		t.Errorf("ssh = %q", got)
	}
	if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallBlocked {
		t.Errorf("smb = %q", got)
	}
	zones = parseFirewalldZones("trusted (active)\n  target: ACCEPT\n")
	if got, _ := firewalldCheck(zones, firewalldServices, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
		t.Errorf("trusted zone = %q", got)
	}
}

func TestParseFirewalldService(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Samba</short>
  <port protocol="udp" port="137"/>
  <port protocol="udp" port="138"/>
  <port port="139" protocol="tcp"/>
  <port protocol="tcp" port="445"/>
  <port protocol="sctp" port="9"/>
  <port protocol="tcp" port="5900-5903"/>
</service>`)
	specs, ok := parseFirewalldService(data)
	if !ok || len(specs) != 5 {
		t.Fatalf("specs = %+v, ok = %v", specs, ok)
	}
	if !anyCovers(specs, shared.ListeningPort{Protocol: "tcp", Port: 5902}) || anyCovers(specs, shared.ListeningPort{Protocol: "udp", Port: 445}) {
		t.Errorf("specs = %+v", specs)
	}
	if _, ok := parseFirewalldService([]byte("<service><port")); ok {
		t.Error("broken XML parsed")
	}
}

func TestALFBlocksAll(t *testing.T) {
	tests := []struct {
		blockAll, global string
		want             bool
	}{
		{"Firewall has block all state set to enabled.", "Firewall is enabled. (State = 1)", true},
		{"Firewall has block all state set to disabled.", "Firewall is enabled. (State = 1)", false},
		{"Block all ENABLED!", "", true},
		{"Block all DISABLED!", "", false},
		{"", "Firewall is blocking all non-essential incoming connections. (State = 2)", true},
		{"", "", false},
	}
	for _, tt := range tests {
		if got := alfBlocksAll(tt.blockAll, tt.global); got != tt.want {
			t.Errorf("alfBlocksAll(%q, %q) = %v, want %v", tt.blockAll, tt.global, got, tt.want)
		}
	}
}

// TestUFW_ScopedRules: ufw lists IPv4 and IPv6 rules separately, and a rule
// can be limited to an interface or a destination address. A rule only
// counts for the sockets it can affect.
func TestUFW_ScopedRules(t *testing.T) {
	const header = "Status: active\nDefault: %s (incoming)\n\nTo                         Action      From\n--                         ------      ----\n"
	tests := []struct {
		name, def, rules, addr, want string
	}{
		// Devin's example: the IPv6 deny doesn't block IPv4 clients.
		{"v6 deny, v4 allow, v4 socket", "deny", "22/tcp (v6)                DENY IN     Anywhere (v6)\n22/tcp                     ALLOW IN    Anywhere\n", "0.0.0.0", firewallAllowed},
		{"v6 deny, v4 allow, v6 socket", "deny", "22/tcp (v6)                DENY IN     Anywhere (v6)\n22/tcp                     ALLOW IN    Anywhere\n", "2001:db8::5", firewallBlocked},
		{"v6 deny, v4 allow, dual-stack socket", "deny", "22/tcp (v6)                DENY IN     Anywhere (v6)\n22/tcp                     ALLOW IN    Anywhere\n", "::", firewallAllowed},
		{"v4 allow only, v6 socket", "deny", "22/tcp                     ALLOW IN    Anywhere\n", "2001:db8::5", firewallBlocked},
		{"interface deny doesn't decide", "allow", "22/tcp on eth0             DENY IN     Anywhere\n", "0.0.0.0", firewallAllowed},
		{"interface deny, default deny", "deny", "22/tcp on eth0             DENY IN     Anywhere\n", "0.0.0.0", firewallBlocked},
		{"interface allow reaches", "deny", "22/tcp on eth1             ALLOW IN    Anywhere\n", "0.0.0.0", firewallAllowed},
		{"destination deny, socket on it", "allow", "10.0.0.5 22/tcp            DENY IN     Anywhere\n", "10.0.0.5", firewallBlocked},
		{"destination deny, socket elsewhere", "allow", "10.0.0.5 22/tcp            DENY IN     Anywhere\n", "10.0.0.6", firewallAllowed},
		{"destination deny, wildcard socket", "allow", "10.0.0.5 22/tcp            DENY IN     Anywhere\n", "0.0.0.0", firewallAllowed},
		{"destination allow, socket elsewhere", "deny", "10.0.0.5 22/tcp            ALLOW IN    Anywhere\n", "10.0.0.6", firewallBlocked},
		{"destination subnet allow", "deny", "10.0.0.0/24 22/tcp         ALLOW IN    Anywhere\n", "10.0.0.6", firewallAllowed},
		{"IPv6 source makes the rule IPv6", "deny", "22/tcp                     ALLOW IN    2001:db8::/32\n", "0.0.0.0", firewallBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := parseUFWStatus(fmt.Sprintf(header, tt.def) + tt.rules)
			got, _ := st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: tt.addr})
			if got != tt.want {
				t.Errorf("verdict = %q, want %q (rules %+v)", got, tt.want, st.rules)
			}
		})
	}
}

func TestListenerFamilies(t *testing.T) {
	tests := []struct {
		addr     string
		families []int
		bound    string
	}{
		{"0.0.0.0", []int{4}, ""},
		{"::", []int{4, 6}, ""},
		{"[::]", []int{4, 6}, ""},
		{"10.0.0.5", []int{4}, "10.0.0.5"},
		{"::ffff:10.0.0.5", []int{4}, "10.0.0.5"},
		{"fe80::1%eth0", []int{6}, "fe80::1"},
		{"*", []int{4, 6}, ""},
	}
	for _, tt := range tests {
		fams, bound := listenerFamilies(tt.addr, false)
		got := ""
		if bound.IsValid() {
			got = bound.String()
		}
		if fmt.Sprint(fams) != fmt.Sprint(tt.families) || got != tt.bound {
			t.Errorf("listenerFamilies(%q) = %v, %q; want %v, %q", tt.addr, fams, got, tt.families, tt.bound)
		}
	}
}

// TestFirewalld_InterfaceZones: a socket bound to one interface is
// governed by that interface's zone (and source zones), not by a zone on
// another interface. Devin's example: SMB on the Wi-Fi address, public on
// Wi-Fi blocks it, trusted on the VPN accepts everything.
func TestFirewalld_InterfaceZones(t *testing.T) {
	zones := parseFirewalldZones(`public (default, active)
  target: default
  interfaces: wlan0
  services: ssh
trusted (active)
  target: ACCEPT
  interfaces: tun0
lab (active)
  target: default
  sources: 10.50.0.0/16
  services: samba
`)
	services := func(name string) ([]portSpec, bool) {
		switch name {
		case "ssh":
			return []portSpec{{protocol: "tcp", from: 22, to: 22}}, true
		case "samba":
			return []portSpec{{protocol: "tcp", from: 139, to: 139}}, true
		}
		return nil, false
	}
	ifaces := func(a netip.Addr) (string, bool) {
		switch a.String() {
		case "192.168.1.20":
			return "wlan0", true
		case "10.8.0.2":
			return "tun0", true
		case "172.17.0.1":
			return "docker0", true // no zone: the default zone applies
		}
		return "", false
	}
	check := firewalldCheck(zones, services, ifaces)
	tests := []struct {
		addr string
		port uint16
		want string
	}{
		{"192.168.1.20", 445, firewallBlocked}, // public blocks SMB; trusted is on another interface
		{"192.168.1.20", 22, firewallAllowed},
		{"192.168.1.20", 139, firewallAllowed}, // the lab source zone reaches every interface
		{"10.8.0.2", 445, firewallAllowed},     // trusted
		{"172.17.0.1", 445, firewallBlocked},   // default zone
		{"0.0.0.0", 445, firewallAllowed},      // wildcard: every active zone, trusted included
		{"192.168.77.7", 445, firewallUnknown}, // interface not found
	}
	for _, tt := range tests {
		if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: tt.port, Address: tt.addr}); got != tt.want {
			t.Errorf("%s:%d = %q, want %q", tt.addr, tt.port, got, tt.want)
		}
	}
	if got, _ := firewalldCheck(zones, services, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "192.168.1.20"}); got != firewallUnknown {
		t.Errorf("no interface lookup: %q, want unknown", got)
	}
}

// TestFirewalld_ServiceNamesValidatedAndCached: odd names from the probe
// output aren't looked up on disk, and each name is looked up once.
func TestFirewalld_ServiceNamesValidatedAndCached(t *testing.T) {
	zones := parseFirewalldZones("public (active)\n  target: default\n  services: ../../etc/passwd ssh ssh\n")
	var looked []string
	check := firewalldCheck(zones, func(name string) ([]portSpec, bool) {
		looked = append(looked, name)
		return []portSpec{{protocol: "tcp", from: 22, to: 22}}, true
	}, nil)
	for _, port := range []uint16{445, 3389, 22} {
		check(shared.ListeningPort{Protocol: "tcp", Port: port})
	}
	if fmt.Sprint(looked) != "[ssh]" {
		t.Errorf("looked up %q, want only ssh, once", looked)
	}
	if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallUnknown {
		t.Errorf("unresolvable name: %q, want unknown", got)
	}
}
