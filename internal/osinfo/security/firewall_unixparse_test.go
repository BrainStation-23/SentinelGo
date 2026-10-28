package security

import (
	"fmt"
	"net/netip"
	"slices"
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
		if got, _ := vp(check(shared.ListeningPort{Protocol: tt.proto, Port: tt.port})); got != tt.want {
			t.Errorf("%s/%d = %q, want %q", tt.proto, tt.port, got, tt.want)
		}
	}
}

func TestUFW_DefaultAllowAndAllPorts(t *testing.T) {
	st := parseUFWStatus("Status: active\nDefault: allow (incoming), allow (outgoing)\n")
	if got, _ := vp(st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445})); got != firewallAllowed {
		t.Errorf("default allow: %q", got)
	}
	st = parseUFWStatus("Status: active\nDefault: reject (incoming)\n\nTo  Action  From\n--  ------  ----\nAnywhere                   ALLOW IN    10.0.0.0/8\n")
	if got, _ := vp(st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445})); got != firewallAllowed {
		t.Errorf("allow all ports from a subnet: %q", got)
	}
	if got, _ := vp(parseUFWStatus("Status: active\nDefault: deny (incoming)\n").check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22})); got != firewallBlocked {
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
	check := firewalldCheck(zones, firewalldServices, nil, nil)
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
		if got, _ := vp(check(shared.ListeningPort{Protocol: tt.proto, Port: tt.port})); got != tt.want {
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
		if got, _ := vp(firewalldCheck(zones, known, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: port})); got != firewallBlocked {
			t.Errorf("tcp/%d = %q, want blocked", port, got)
		}
	}
}

func TestFirewalld_DefaultZoneWhenNoneActive(t *testing.T) {
	zones := parseFirewalldZones("public (default)\n  target: default\n  services: ssh\ntrusted\n  target: ACCEPT\n")
	check := firewalldCheck(zones, firewalldServices, nil, nil)
	if got, _ := vp(check(shared.ListeningPort{Protocol: "tcp", Port: 22})); got != firewallAllowed {
		t.Errorf("ssh = %q", got)
	}
	if got, _ := vp(check(shared.ListeningPort{Protocol: "tcp", Port: 445})); got != firewallBlocked {
		t.Errorf("smb = %q", got)
	}
	zones = parseFirewalldZones("trusted (active)\n  target: ACCEPT\n")
	if got, _ := vp(firewalldCheck(zones, firewalldServices, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445})); got != firewallAllowed {
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
			got, _ := vp(st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: tt.addr}))
			if got != tt.want {
				t.Errorf("verdict = %q, want %q (rules %+v)", got, tt.want, st.rules)
			}
		})
	}
}

func TestUFW_ArrivalInterfaces(t *testing.T) {
	st := parseUFWStatus("Status: active\nDefault: allow (incoming)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp on eth0             DENY IN     Anywhere\n")
	tests := []struct {
		name    string
		arrival []string
		want    string
	}{
		{"only interface", []string{"eth0"}, firewallBlocked},
		{"another interface up", []string{"eth0", "wlan0"}, firewallAllowed},
		{"only interface is another", []string{"wlan0"}, firewallAllowed},
		{"none up", []string{}, firewallAllowed},
		{"unknown", nil, firewallAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := vp(st.check(nil, newUFWHost(nil, tt.arrival))(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "0.0.0.0"}))
			if got != tt.want {
				t.Errorf("verdict = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUFW_V6OnlyFromIPv4Pair(t *testing.T) {
	// IPv4 allowed, IPv6 denied: a "::" socket is reachable only if it
	// also accepts IPv4.
	st := parseUFWStatus("Status: active\nDefault: deny (incoming)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp (v6)                DENY IN     Anywhere (v6)\n22/tcp                     ALLOW IN    Anywhere\n")
	v6 := shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "::"}
	tests := []struct {
		name  string
		ports []shared.ListeningPort
		want  string
	}{
		{"alone is dual-stack", []shared.ListeningPort{v6}, firewallAllowed},
		{"paired with 0.0.0.0 is IPv6-only", []shared.ListeningPort{v6, {Protocol: "tcp", Port: 22, Address: "0.0.0.0"}}, firewallBlocked},
		{"pair on another port", []shared.ListeningPort{v6, {Protocol: "tcp", Port: 23, Address: "0.0.0.0"}}, firewallAllowed},
		{"pair on another protocol", []shared.ListeningPort{v6, {Protocol: "udp", Port: 22, Address: "0.0.0.0"}}, firewallAllowed},
		{"pair bound to one address", []shared.ListeningPort{v6, {Protocol: "tcp", Port: 22, Address: "10.0.0.5"}}, firewallAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := vp(st.check(nil, newUFWHost(tt.ports, nil))(v6)); got != tt.want {
				t.Errorf("verdict = %q, want %q", got, tt.want)
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
	check := firewalldCheck(zones, services, ifaces, nil)
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
		if got, _ := vp(check(shared.ListeningPort{Protocol: "tcp", Port: tt.port, Address: tt.addr})); got != tt.want {
			t.Errorf("%s:%d = %q, want %q", tt.addr, tt.port, got, tt.want)
		}
	}
	if got, _ := vp(firewalldCheck(zones, services, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "192.168.1.20"})); got != firewallUnknown {
		t.Errorf("no interface lookup: %q, want unknown", got)
	}
}

// TestFirewalld_DefaultZoneForUnboundInterfaces: Devin's example. The
// default zone opens SSH and isn't bound to any interface, a restrictive
// zone is bound to tun0. A wildcard socket also gets traffic on eth0, which
// no zone claims, so the default zone governs it too.
func TestFirewalld_DefaultZoneForUnboundInterfaces(t *testing.T) {
	zones := parseFirewalldZones("public (default)\n  target: default\n  services: ssh\nvpn (active)\n  target: default\n  interfaces: tun0\n")
	tests := []struct {
		name    string
		arrival []string
		want    string
	}{
		{"another interface has no zone", []string{"eth0", "tun0"}, firewallAllowed},
		{"interfaces unknown", nil, firewallAllowed},
		{"every interface has a zone", []string{"tun0"}, firewallBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := vp(firewalldCheck(zones, firewalldServices, nil, tt.arrival)(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "0.0.0.0"})); got != tt.want {
				t.Errorf("ssh = %q, want %q", got, tt.want)
			}
		})
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
	}, nil, nil)
	for _, port := range []uint16{445, 3389, 22} {
		check(shared.ListeningPort{Protocol: "tcp", Port: port})
	}
	if fmt.Sprint(looked) != "[ssh]" {
		t.Errorf("looked up %q, want only ssh, once", looked)
	}
	if got, _ := vp(check(shared.ListeningPort{Protocol: "tcp", Port: 445})); got != firewallUnknown {
		t.Errorf("unresolvable name: %q, want unknown", got)
	}
}

// TestUFW_RemoteScope: an allow from Anywhere admits any address, one from
// an address or prefix only that source (#251).
func TestUFW_RemoteScope(t *testing.T) {
	// "Samba Custom" resolves here; TestUFW_UnresolvedAllowScope covers it not.
	apps := parseUFWAppProfiles([]string{ufwAppFixture, "[Samba Custom]\nports=139,445/tcp\n"})
	check := parseUFWStatus(ufwVerboseFixture).check(apps, ufwHost{})
	tests := []struct {
		port         uint16
		verdict      string
		scope        string
		wantAddrList []string
	}{
		{22, firewallAllowed, remoteAny, nil},                               // OpenSSH from Anywhere
		{5432, firewallAllowed, remoteSpecific, []string{"192.168.1.0/24"}}, // narrow deny, then allow from a subnet
		{3306, firewallBlocked, "", nil},                                    // deny from Anywhere first
		{5901, firewallAllowed, remoteAny, nil},                             // LIMIT from Anywhere
	}
	for _, tt := range tests {
		r := check(shared.ListeningPort{Protocol: "tcp", Port: tt.port, Address: "0.0.0.0"})
		scope, addrs := reportedScope(r)
		if r.verdict != tt.verdict || scope != tt.scope || !slices.Equal(addrs, tt.wantAddrList) {
			t.Errorf("tcp/%d: %q, %q, %q; want %q, %q, %q", tt.port, r.verdict, scope, addrs, tt.verdict, tt.scope, tt.wantAddrList)
		}
	}

	// An allow from a subnet, then one from anywhere: the widest wins. A
	// deny from anywhere before it stops the scan.
	st := parseUFWStatus("Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n" +
		"445/tcp  ALLOW IN  10.0.0.0/8\n445/tcp  ALLOW IN  Anywhere\n" +
		"139/tcp  ALLOW IN  10.0.0.0/8\n139/tcp  DENY IN  Anywhere\n139/tcp  ALLOW IN  Anywhere\n")
	if scope, _ := reportedScope(st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0"})); scope != remoteAny {
		t.Errorf("subnet + anywhere: %q, want any", scope)
	}
	r := st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 139, Address: "0.0.0.0"})
	if scope, addrs := reportedScope(r); r.verdict != firewallAllowed || scope != remoteSpecific || !slices.Equal(addrs, []string{"10.0.0.0/8"}) {
		t.Errorf("subnet, deny all, anywhere: %q, %q, %q; want allowed, specific, [10.0.0.0/8]", r.verdict, scope, addrs)
	}

	st = parseUFWStatus("Status: active\nDefault: allow (incoming)\n")
	if scope, _ := reportedScope(st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0"})); scope != remoteAny {
		t.Errorf("default allow: %q, want any", scope)
	}
}

// TestUFW_UnresolvedAllowScope: an allow naming a profile that isn't
// installed may let its sources in, so it widens an allowed port's scope.
func TestUFW_UnresolvedAllowScope(t *testing.T) {
	const head = "Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n5432/tcp  ALLOW IN  192.168.1.0/24\n"
	tests := []struct {
		name  string
		rule  string
		scope string
		addrs []string
	}{
		{"from anywhere", "Missing  ALLOW IN  Anywhere\n", remoteUnknown, nil},
		{"from a subnet", "Missing  ALLOW IN  10.0.0.0/8\n", remoteSpecific, []string{"192.168.1.0/24", "10.0.0.0/8"}},
		{"a deny", "Missing  DENY IN  Anywhere\n", remoteSpecific, []string{"192.168.1.0/24"}},
	}
	for _, tt := range tests {
		r := parseUFWStatus(head+tt.rule).check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 5432, Address: "0.0.0.0"})
		if scope, addrs := reportedScope(r); r.verdict != firewallAllowed || scope != tt.scope || !slices.Equal(addrs, tt.addrs) {
			t.Errorf("%s: %q, %q, %q; want allowed, %q, %q", tt.name, r.verdict, scope, addrs, tt.scope, tt.addrs)
		}
	}

	// IPv4 allows from a subnet; IPv6 has only an unresolved rule. The
	// dual-stack socket's scope is unknown.
	st := parseUFWStatus("Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n" +
		"22/tcp  ALLOW IN  10.0.0.0/8\nMissing (v6)  ALLOW IN  Anywhere (v6)\n")
	r := st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "::"})
	if scope, _ := reportedScope(r); r.verdict != firewallAllowed || scope != remoteUnknown {
		t.Errorf("dual-stack, one family unknown: %q, %q; want allowed, unknown", r.verdict, scope)
	}

	// The unknown family's unresolved allow is from a subnet: still specific.
	st = parseUFWStatus("Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n" +
		"22/tcp  ALLOW IN  10.0.0.0/8\nMissing (v6)  ALLOW IN  fd00::/8 (v6)\n")
	r = st.check(nil, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "::"})
	if scope, addrs := reportedScope(r); r.verdict != firewallAllowed || scope != remoteSpecific || !slices.Equal(addrs, []string{"10.0.0.0/8", "fd00::/8"}) {
		t.Errorf("dual-stack, unknown family from a subnet: %q, %q, %q; want allowed, specific, [10.0.0.0/8 fd00::/8]", r.verdict, scope, addrs)
	}
}

// TestFirewalld_RemoteScope: a rich rule with a source, or a zone bound to
// sources, admits only them; anything else admits any address (#251).
func TestFirewalld_RemoteScope(t *testing.T) {
	// custom-db resolves here; TestFirewalld_UnresolvedServiceScope covers it not.
	services := func(name string) ([]portSpec, bool) {
		if name == "custom-db" {
			return []portSpec{{protocol: "tcp", from: 1521, to: 1521}}, true
		}
		return firewalldServices(name)
	}
	check := firewalldCheck(parseFirewalldZones(firewalldFixture), services, nil, nil)
	tests := []struct {
		port         uint16
		scope        string
		wantAddrList []string
	}{
		{22, remoteAny, nil},                            // ssh service in the public zone
		{445, remoteSpecific, []string{"10.0.0.0/8"}},   // rich rule with a source
		{6379, remoteSpecific, []string{"10.1.0.0/16"}}, // rich service rule with a source
		{5903, remoteAny, nil},                          // port range
	}
	for _, tt := range tests {
		r := check(shared.ListeningPort{Protocol: "tcp", Port: tt.port, Address: "0.0.0.0"})
		scope, addrs := reportedScope(r)
		if r.verdict != firewallAllowed || scope != tt.scope || !slices.Equal(addrs, tt.wantAddrList) {
			t.Errorf("tcp/%d: %q, %q, %q; want allowed, %q, %q", tt.port, r.verdict, scope, addrs, tt.scope, tt.wantAddrList)
		}
	}

	zones := parseFirewalldZones("public (default, active)\n  target: default\n  interfaces: eth0\n  services:\n" +
		"internal (active)\n  target: default\n  sources: 10.20.0.0/16 192.168.7.0/24\n  services: ssh\n" +
		"  rich rules:\n\trule family=\"ipv4\" source NOT address=\"10.20.9.9\" port port=\"445\" protocol=\"tcp\" accept\n")
	r := firewalldCheck(zones, firewalldServices, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: 22, Address: "0.0.0.0"})
	if scope, addrs := reportedScope(r); r.verdict != firewallAllowed || scope != remoteSpecific || !slices.Equal(addrs, []string{"10.20.0.0/16", "192.168.7.0/24"}) {
		t.Errorf("source-bound zone: %q, %q, %q", r.verdict, scope, addrs)
	}
	r = firewalldCheck(zones, firewalldServices, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0"})
	if scope, addrs := reportedScope(r); scope != remoteSpecific || !slices.Equal(addrs, []string{"10.20.0.0/16", "192.168.7.0/24"}) {
		t.Errorf("NOT-source rich rule in a source-bound zone: %q, %q; want the zone's sources", scope, addrs)
	}
}

// TestFirewalld_UnresolvedServiceScope: a service that can't be resolved may
// let its zone's traffic in, so it widens an allowed port's scope; another
// zone's unresolved service does too.
func TestFirewalld_UnresolvedServiceScope(t *testing.T) {
	tests := []struct {
		name  string
		zones string
		scope string
	}{
		{"same zone, any source", "public (default, active)\n  interfaces: eth0\n  services: missing\n  rich rules:\n\trule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"445\" protocol=\"tcp\" accept\n", remoteUnknown},
		{"source-only zone", "internal (active)\n  sources: 10.0.0.0/8\n  services: missing\n  rich rules:\n\trule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"445\" protocol=\"tcp\" accept\n", remoteSpecific},
		{"another zone", "public (default, active)\n  interfaces: eth0\n  services: missing\n" +
			"internal (active)\n  sources: 10.0.0.0/8\n  ports: 445/tcp\n", remoteUnknown},
		{"another source-only zone", "internal (active)\n  sources: 10.0.0.0/8\n  ports: 445/tcp\n" +
			"lab (active)\n  sources: 172.16.0.0/12\n  services: missing\n", remoteSpecific},
	}
	for _, tt := range tests {
		r := firewalldCheck(parseFirewalldZones(tt.zones), firewalldServices, nil, nil)(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0"})
		if scope, _ := reportedScope(r); r.verdict != firewallAllowed || scope != tt.scope {
			t.Errorf("%s: %q, %q; want allowed, %q", tt.name, r.verdict, scope, tt.scope)
		}
	}
}

// TestFirewalld_InterfaceAndSourceZone: a zone bound to an interface as well
// as sources takes all of that interface's traffic, so it lets any address in.
func TestFirewalld_InterfaceAndSourceZone(t *testing.T) {
	zones := parseFirewalldZones("internal (active)\n  interfaces: eth1\n  sources: 10.0.0.0/8\n  ports: 445/tcp\n" +
		"public (default, active)\n  interfaces: eth0\n")
	r := firewalldCheck(zones, firewalldServices, nil, []string{"eth0", "eth1"})(shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0"})
	if scope, _ := reportedScope(r); r.verdict != firewallAllowed || scope != remoteAny {
		t.Errorf("interface + sources: %q, %q; want allowed, any", r.verdict, scope)
	}
}

// TestLinuxChecks_EveryInterface: Linux accepts a packet for any local
// address on any interface, so an allow limited to one interface names no
// interface: a public address elsewhere still counts.
func TestLinuxChecks_EveryInterface(t *testing.T) {
	apps := parseUFWAppProfiles([]string{ufwAppFixture, "[Samba Custom]\nports=139,445/tcp\n"})
	r := parseUFWStatus(ufwVerboseFixture).check(apps, ufwHost{})(shared.ListeningPort{Protocol: "tcp", Port: 27017, Address: "0.0.0.0"})
	if r.verdict != firewallAllowed || !r.via.includes("eth0") {
		t.Errorf("ufw 27017 on eth1: %q, via %+v; want allowed, every interface", r.verdict, r.via)
	}
	zones := parseFirewalldZones("public (default, active)\n  interfaces: eth0\nwork (active)\n  interfaces: eth2\n  ports: 3389/tcp\n")
	r = firewalldCheck(zones, firewalldServices, nil, []string{"eth0", "eth2"})(shared.ListeningPort{Protocol: "tcp", Port: 3389, Address: "0.0.0.0"})
	if r.verdict != firewallAllowed || !r.via.includes("eth0") {
		t.Errorf("firewalld zone on eth2: %q, via %+v; want allowed, every interface", r.verdict, r.via)
	}
}
