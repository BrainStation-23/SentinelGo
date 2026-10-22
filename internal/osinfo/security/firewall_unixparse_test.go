package security

import (
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
	check := st.check(parseUFWAppProfiles([]string{ufwAppFixture}))

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
	if got, _ := st.check(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
		t.Errorf("default allow: %q", got)
	}
	st = parseUFWStatus("Status: active\nDefault: reject (incoming)\n\nTo  Action  From\n--  ------  ----\nAnywhere                   ALLOW IN    10.0.0.0/8\n")
	if got, _ := st.check(nil)(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
		t.Errorf("allow all ports from a subnet: %q", got)
	}
	if got, _ := parseUFWStatus("Status: active\nDefault: deny (incoming)\n").check(nil)(shared.ListeningPort{Protocol: "tcp", Port: 22}); got != firewallBlocked {
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
	check := firewalldCheck(zones, firewalldServices)
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
		if got, _ := firewalldCheck(zones, known)(shared.ListeningPort{Protocol: "tcp", Port: port}); got != firewallBlocked {
			t.Errorf("tcp/%d = %q, want blocked", port, got)
		}
	}
}

func TestFirewalld_DefaultZoneWhenNoneActive(t *testing.T) {
	zones := parseFirewalldZones("public (default)\n  target: default\n  services: ssh\ntrusted\n  target: ACCEPT\n")
	check := firewalldCheck(zones, firewalldServices)
	if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: 22}); got != firewallAllowed {
		t.Errorf("ssh = %q", got)
	}
	if got, _ := check(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallBlocked {
		t.Errorf("smb = %q", got)
	}
	zones = parseFirewalldZones("trusted (active)\n  target: ACCEPT\n")
	if got, _ := firewalldCheck(zones, firewalldServices)(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != firewallAllowed {
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
