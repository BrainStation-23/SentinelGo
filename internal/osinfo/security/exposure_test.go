package security

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// The exposure analysis reads the host's addresses to tell whether a
// wildcard socket is on a public address; tests start from a host with none.
func init() { hostAddrs = func() []hostAddr { return nil } }

// stubHostAddrs makes the host's interface addresses addrs for one test:
// "eth1 8.8.8.8", or a bare address on eth0.
func stubHostAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	orig := hostAddrs
	t.Cleanup(func() { hostAddrs = orig })
	var parsed []hostAddr
	for _, a := range addrs {
		iface, addr, ok := strings.Cut(a, " ")
		if !ok {
			iface, addr = "eth0", a
		}
		parsed = append(parsed, hostAddr{iface: iface, addr: netip.MustParseAddr(addr)})
	}
	hostAddrs = func() []hostAddr { return parsed }
}

// vp returns a firewall result's verdict and profiles, for tests written
// against the (verdict, profiles) pair.
func vp(r firewallResult) (string, []string) { return r.verdict, r.profiles }

func TestBindScope(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.1", scopeLoopback},
		{"127.0.0.53", scopeLoopback}, // systemd-resolved
		{"127.1.2.3", scopeLoopback},
		{"::1", scopeLoopback},
		{"[::1]", scopeLoopback},
		{"::ffff:127.0.0.1", scopeLoopback},
		{"localhost", scopeLoopback},
		{"0.0.0.0", scopeAll},
		{"::", scopeAll},
		{"[::]", scopeAll},
		{"*", scopeAll},
		{"192.168.1.23", scopeInterface},
		{"10.0.0.5", scopeInterface},
		{"fe80::1%eth0", scopeInterface},
		{"2001:db8::1", scopeInterface},
		{"", scopeUnknown},
		{"not-an-address", scopeUnknown},
	}
	for _, tt := range tests {
		if got := bindScope(tt.addr); got != tt.want {
			t.Errorf("bindScope(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestRiskyServiceName(t *testing.T) {
	tests := []struct {
		proto string
		port  uint16
		want  string // "" = not risky
	}{
		{"tcp", 21, "FTP"},
		{"tcp", 22, "SSH"},
		{"tcp", 23, "Telnet"},
		{"udp", 137, "NetBIOS"},
		{"udp", 138, "NetBIOS"},
		{"tcp", 139, "SMB"},
		{"udp", 161, "SNMP"},
		{"tcp", 445, "SMB"},
		{"tcp", 1433, "MSSQL"},
		{"tcp", 2375, "Docker API"},
		{"tcp", 2376, "Docker API"},
		{"tcp", 3306, "MySQL"},
		{"tcp", 3389, "RDP"},
		{"udp", 3389, "RDP"},
		{"tcp", 5432, "PostgreSQL"},
		{"tcp", 5900, "VNC"},
		{"tcp", 5906, "VNC"},
		{"tcp", 5985, "WinRM"},
		{"tcp", 5986, "WinRM"},
		{"tcp", 6379, "Redis"},
		{"tcp", 9200, "Elasticsearch"},
		{"tcp", 10250, "Kubelet"},
		{"tcp", 27017, "MongoDB"},
		{"TCP", 445, "SMB"}, // protocol case doesn't matter
		// Not risky: wrong protocol, or OS/browser noise.
		{"udp", 445, ""},
		{"tcp", 137, ""},
		{"tcp", 161, ""},
		{"tcp", 5907, ""},
		{"tcp", 135, ""},
		{"udp", 5353, ""},
		{"udp", 3702, ""},
		{"tcp", 5040, ""},
	}
	for _, tt := range tests {
		got, ok := riskyServiceName(shared.ListeningPort{Protocol: tt.proto, Port: tt.port})
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("riskyServiceName(%s/%d) = %q, %v; want %q", tt.proto, tt.port, got, ok, tt.want)
		}
	}
}

// stockWindowsPorts is a Windows 11 workstation's listeners without SMB, RDP,
// WinRM or SSH: dozens of non-loopback binds, none of them risky.
func stockWindowsPorts() []shared.ListeningPort {
	ports := []shared.ListeningPort{
		{Protocol: "tcp", Port: 135, Address: "0.0.0.0", ProcessName: "svchost.exe"},
		{Protocol: "tcp", Port: 135, Address: "::", ProcessName: "svchost.exe"},
		{Protocol: "tcp", Port: 5040, Address: "0.0.0.0", ProcessName: "svchost.exe"},
		{Protocol: "udp", Port: 3702, Address: "0.0.0.0", ProcessName: "svchost.exe"},
		{Protocol: "tcp", Port: 49664, Address: "0.0.0.0", ProcessName: "lsass.exe"},
	}
	for i := 0; i < 40; i++ {
		ports = append(ports, shared.ListeningPort{Protocol: "udp", Port: 5353, Address: "0.0.0.0", ProcessName: "msedge.exe"})
	}
	return ports
}

func TestNetworkExposure_StockWindowsIsLow(t *testing.T) {
	info := analyzeNetworkExposure(stockWindowsPorts(), nil)
	if info.PubliclyBoundPorts != 45 {
		t.Errorf("PubliclyBoundPorts = %d, want 45 (meaning unchanged: non-loopback binds)", info.PubliclyBoundPorts)
	}
	if len(info.OpenAdministrativePorts) != 0 || len(info.RiskyServices) != 0 {
		t.Errorf("admin ports %v, risky %v; want none", info.OpenAdministrativePorts, info.RiskyServices)
	}
	if level, recs := summarizeNetworkExposureLevel(info); level != "Low" || recs != nil {
		t.Errorf("level = %q, %q; want Low with no recommendation", level, recs)
	}
}

func TestNetworkExposure_SMBOnAllInterfaces(t *testing.T) {
	ports := append(stockWindowsPorts(), shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0", ProcessName: "System"})
	for _, tt := range []struct {
		verdict, level, remote string
	}{
		{firewallAllowed, "High", remoteUnknown}, // a check that can't tell from where
		{firewallDisabled, "High", remoteAny},
		{firewallUnknown, "High", ""},
		{firewallBlocked, "Medium", ""},
	} {
		check := constantCheck(tt.verdict)
		info := analyzeNetworkExposure(ports, check)
		if !slices.Equal(info.OpenAdministrativePorts, []uint16{445}) {
			t.Errorf("%s: OpenAdministrativePorts = %v, want [445]", tt.verdict, info.OpenAdministrativePorts)
		}
		want := shared.RiskyService{Name: "SMB", Port: 445, Protocol: "tcp", Address: "0.0.0.0", Scope: scopeAll, ProcessName: "System", Firewall: tt.verdict, RemoteScope: tt.remote}
		if len(info.RiskyServices) != 1 || fmt.Sprint(info.RiskyServices[0]) != fmt.Sprint(want) {
			t.Errorf("%s: RiskyServices = %+v, want [%+v]", tt.verdict, info.RiskyServices, want)
		}
		level, recs := summarizeNetworkExposureLevel(info)
		if level != tt.level {
			t.Errorf("%s: level = %q, want %q", tt.verdict, level, tt.level)
		}
		if len(recs) != 1 || !strings.Contains(recs[0], "SMB (445/tcp)") {
			t.Errorf("%s: recommendations = %q, want one naming SMB (445/tcp)", tt.verdict, recs)
		}
	}
}

func TestNetworkExposure_LoopbackNeverCounts(t *testing.T) {
	ports := []shared.ListeningPort{
		{Protocol: "tcp", Port: 22, Address: "127.0.0.1", ProcessName: "sshd"},
		{Protocol: "udp", Port: 53, Address: "127.0.0.53", ProcessName: "systemd-resolved"},
		{Protocol: "tcp", Port: 5985, Address: "::1", ProcessName: "System"},
		{Protocol: "tcp", Port: 3306, Address: "::ffff:127.0.0.1", ProcessName: "mysqld"},
	}
	info := analyzeNetworkExposure(ports, nil)
	if info.PubliclyBoundPorts != 0 || len(info.OpenAdministrativePorts) != 0 || len(info.RiskyServices) != 0 || len(info.RemoteAccessServices) != 0 {
		t.Errorf("loopback listeners counted: %+v", info)
	}
	if info.TotalListeningPorts != 4 || len(info.ActiveNetworkServices) != 4 {
		t.Errorf("total = %d, services = %v; want all 4 still listed", info.TotalListeningPorts, info.ActiveNetworkServices)
	}
	if level, _ := summarizeNetworkExposureLevel(info); level != "Low" {
		t.Errorf("level = %q, want Low", level)
	}
}

func TestNetworkExposure_InterfaceBindIsRisky(t *testing.T) {
	info := analyzeNetworkExposure([]shared.ListeningPort{
		{Protocol: "tcp", Port: 139, Address: "192.168.1.23", ProcessName: "System"},
	}, nil)
	if info.PubliclyBoundPorts != 1 || !slices.Equal(info.OpenAdministrativePorts, []uint16{139}) {
		t.Errorf("public = %d, admin = %v; want 1, [139]", info.PubliclyBoundPorts, info.OpenAdministrativePorts)
	}
	if len(info.RiskyServices) != 1 || info.RiskyServices[0].Scope != scopeInterface || info.RiskyServices[0].Firewall != firewallUnknown {
		t.Errorf("RiskyServices = %+v, want one interface-scoped SMB with verdict unknown", info.RiskyServices)
	}
}

func TestNetworkExposure_RiskyServicesSortedAndDeduped(t *testing.T) {
	ports := []shared.ListeningPort{
		{Protocol: "tcp", Port: 445, Address: "::", ProcessName: "System"},
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", ProcessName: "sshd"},
		{Protocol: "tcp", Port: 445, Address: "0.0.0.0", ProcessName: "System"},
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", ProcessName: "sshd"}, // duplicate socket
	}
	info := analyzeNetworkExposure(ports, func(p shared.ListeningPort) firewallResult {
		if p.Port == 22 {
			return firewallResult{verdict: firewallAllowed, profiles: []string{"Public"}, scope: remoteScope{kind: remoteAny}}
		}
		return firewallResult{verdict: firewallBlocked}
	})
	var got []string
	for _, s := range info.RiskyServices {
		got = append(got, fmt.Sprintf("%d %s %s %v", s.Port, s.Address, s.Firewall, s.ReachableProfiles))
	}
	want := []string{"22 0.0.0.0 allowed [Public]", "445 0.0.0.0 blocked []", "445 :: blocked []"}
	if !slices.Equal(got, want) {
		t.Errorf("RiskyServices = %q, want %q", got, want)
	}
	if !slices.Equal(info.OpenAdministrativePorts, []uint16{22, 445}) {
		t.Errorf("OpenAdministrativePorts = %v, want [22 445]", info.OpenAdministrativePorts)
	}
	level, recs := summarizeNetworkExposureLevel(info)
	if level != "High" || len(recs) != 1 || !strings.Contains(recs[0], "SSH (22/tcp)") || strings.Contains(recs[0], "SMB") {
		t.Errorf("level = %q, recs = %q; want High naming only SSH", level, recs)
	}
}

// TestSummarizeNetworkExposureLevel_ExposedWinsOverBlocked: the same service
// blocked on one address and reachable on another is listed once, as exposed.
func TestSummarizeNetworkExposureLevel_ExposedWinsOverBlocked(t *testing.T) {
	net := shared.NetworkExposureAccessInfo{RiskyServices: []shared.RiskyService{
		{Name: "SMB", Port: 445, Protocol: "tcp", Firewall: firewallBlocked},
		{Name: "SMB", Port: 445, Protocol: "tcp", Firewall: firewallAllowed},
	}}
	level, recs := summarizeNetworkExposureLevel(net)
	if level != "High" || len(recs) != 1 || strings.Count(recs[0], "SMB") != 1 {
		t.Errorf("level = %q, recs = %q", level, recs)
	}
}

// TestComputePostureScore_ExposureMediumKeepsPoint: only High exposure costs
// the posture point, so a device whose risky services are all firewalled
// isn't marked down for them.
func TestComputePostureScore_ExposureMediumKeepsPoint(t *testing.T) {
	var fw shared.FirewallSecurityInfo
	var enc shared.DeviceEncryptionInfo
	var id shared.IdentityAccessControlInfo
	for exposure, want := range map[string]int{"Low": 1, "Medium": 1, "High": 0} {
		if got := computePostureScore(fw, enc, id, postureRatings{exposure: exposure}); got != want {
			t.Errorf("exposure %s: score = %d, want %d", exposure, got, want)
		}
	}
}

// TestRiskyServicePastUploadCap: the exposure analysis sees every listener,
// even when the uploaded listening_ports list is capped before the risky one.
func TestRiskyServicePastUploadCap(t *testing.T) {
	var ports []shared.ListeningPort
	for i := 0; i < maxListeningPorts; i++ {
		ports = append(ports, shared.ListeningPort{Protocol: "udp", Port: 5353, Address: "0.0.0.0", ProcessName: "msedge.exe"})
	}
	ports = append(ports, shared.ListeningPort{Protocol: "tcp", Port: 445, Address: "0.0.0.0", ProcessName: "System"})

	if got := uploadedListeningPorts(ports); len(got) != maxListeningPorts {
		t.Errorf("uploaded %d listeners, want %d", len(got), maxListeningPorts)
	}
	if got := uploadedListeningPorts(ports[:3]); len(got) != 3 {
		t.Errorf("short list changed: %d", len(got))
	}
	info := analyzeNetworkExposure(ports, nil)
	if len(info.RiskyServices) != 1 || info.RiskyServices[0].Port != 445 {
		t.Errorf("RiskyServices = %+v, want SMB past the upload cap", info.RiskyServices)
	}
}

func TestOnPublicAddress(t *testing.T) {
	eth1 := ifaceSet{names: []string{"eth1"}}
	tests := []struct {
		addr   string
		host   []string
		via    ifaceSet
		v6Only bool
		want   bool
	}{
		{"8.8.8.8", nil, ifaceSet{}, false, true},         // public IPv4 (bound)
		{"10.103.2.126", nil, ifaceSet{}, false, false},   // RFC 1918
		{"192.168.1.5", nil, ifaceSet{}, false, false},    // RFC 1918
		{"100.72.1.9", nil, ifaceSet{}, false, false},     // CGNAT
		{"198.18.0.1", nil, ifaceSet{}, false, false},     // benchmarking
		{"203.0.113.10", nil, ifaceSet{}, false, false},   // documentation
		{"240.0.0.1", nil, ifaceSet{}, false, false},      // reserved
		{"2606:4700::1111", nil, ifaceSet{}, false, true}, // global unicast IPv6
		{"2001:db8::5", nil, ifaceSet{}, false, false},    // documentation
		{"fd12:3456::1", nil, ifaceSet{}, false, false},   // ULA
		{"fe80::1%eth0", nil, ifaceSet{}, false, false},   // link-local
		{"127.0.0.1", nil, ifaceSet{}, false, false},      // loopback
		{"::ffff:8.8.8.8", nil, ifaceSet{}, false, true},  // v4-mapped public
		{"0.0.0.0", []string{"10.0.0.5", "8.8.4.4"}, ifaceSet{}, false, true},
		{"0.0.0.0", []string{"10.0.0.5", "2606:4700::7"}, ifaceSet{}, false, false}, // only v6 is public
		{"::", []string{"10.0.0.5", "2606:4700::7"}, ifaceSet{}, false, true},
		{"::", []string{"8.8.4.4", "fd00::7"}, ifaceSet{}, false, true}, // dual-stack
		{"::", []string{"8.8.4.4", "fd00::7"}, ifaceSet{}, true, false}, // IPv6-only
		{"*", []string{"10.0.0.5", "fd00::7"}, ifaceSet{}, false, false},
		// The firewall lets connections in only on eth1.
		{"0.0.0.0", []string{"eth0 8.8.4.4", "eth1 10.0.0.5"}, eth1, false, false},
		{"0.0.0.0", []string{"eth0 10.0.0.5", "eth1 8.8.4.4"}, eth1, false, true},
		{"0.0.0.0", []string{"eth0 8.8.4.4"}, ifaceSet{every: true, names: []string{"eth1"}}, false, true},
		{"8.8.4.4", []string{"eth0 8.8.4.4"}, eth1, false, false},
		{"8.8.4.4", []string{"eth1 8.8.4.4"}, eth1, false, true},
	}
	for _, tt := range tests {
		stubHostAddrs(t, tt.host...)
		if got := onPublicAddress(tt.addr, tt.via, tt.v6Only); got != tt.want {
			t.Errorf("onPublicAddress(%q, %+v, v6Only %v) with host %v = %v, want %v", tt.addr, tt.via, tt.v6Only, tt.host, got, tt.want)
		}
	}
}

// A service let in only on the private network isn't rated Critical though
// the host has a public address on another network.
func TestFindRiskyServices_PublicOnlyThroughAllowingInterface(t *testing.T) {
	stubHostAddrs(t, "wifi 8.8.4.4", "lan 192.168.1.5")
	ports := []shared.ListeningPort{{Protocol: "tcp", Port: 445, Address: "0.0.0.0"}}
	check := func(via ...string) firewallCheck {
		return func(shared.ListeningPort) firewallResult {
			r := firewallResult{verdict: firewallAllowed, scope: remoteScope{kind: remoteAny}}
			for _, v := range via {
				r.via.add(v)
			}
			return r
		}
	}
	if got := findRiskyServices(ports, check("lan")); got[0].OnPublicAddress {
		t.Error("allowed on lan only: OnPublicAddress = true")
	}
	if got := findRiskyServices(ports, check("wifi")); !got[0].OnPublicAddress {
		t.Error("allowed on wifi: OnPublicAddress = false")
	}
	if got := findRiskyServices(ports, check()); !got[0].OnPublicAddress {
		t.Error("allowed on unknown interfaces: OnPublicAddress = false")
	}
}

// A "::" socket beside a 0.0.0.0 one on the same port accepts IPv6 only, so
// a public IPv4 address doesn't make it public.
func TestFindRiskyServices_IPv6OnlyWildcard(t *testing.T) {
	stubHostAddrs(t, "8.8.4.4", "fd00::7")
	ports := []shared.ListeningPort{
		{Protocol: "tcp", Port: 445, Address: "::"},
		{Protocol: "tcp", Port: 445, Address: "0.0.0.0"},
		{Protocol: "tcp", Port: 3389, Address: "::"},
	}
	public := map[string]bool{}
	for _, s := range findRiskyServices(ports, nil) {
		public[fmt.Sprintf("%d %s", s.Port, s.Address)] = s.OnPublicAddress
	}
	want := map[string]bool{"445 ::": false, "445 0.0.0.0": true, "3389 ::": true}
	for k, v := range want {
		if public[k] != v {
			t.Errorf("%s: OnPublicAddress = %v, want %v", k, public[k], v)
		}
	}
}

func TestSystemInterfaceAddrs(t *testing.T) {
	orig := listInterfaces
	t.Cleanup(func() { listInterfaces = orig })
	ipnet := func(s string) net.Addr {
		_, n, _ := net.ParseCIDR(s)
		n.IP = net.ParseIP(strings.Split(s, "/")[0])
		return n
	}
	listInterfaces = func() ([]netInterface, error) {
		return []netInterface{
			{name: "eth0", up: true, addrs: []net.Addr{ipnet("8.8.4.4/24"), ipnet("::ffff:10.0.0.5/120"), &net.IPAddr{IP: net.ParseIP("1.1.1.1")}}},
			{name: "eth1", up: false, addrs: []net.Addr{ipnet("9.9.9.9/24")}},
		}, nil
	}
	got := systemInterfaceAddrs()
	want := []hostAddr{{"eth0", netip.MustParseAddr("8.8.4.4")}, {"eth0", netip.MustParseAddr("10.0.0.5")}}
	if !slices.Equal(got, want) {
		t.Errorf("systemInterfaceAddrs() = %v, want %v (down interfaces skipped, v4-mapped unmapped)", got, want)
	}
	listInterfaces = func() ([]netInterface, error) { return nil, errors.New("no interfaces") }
	if got := systemInterfaceAddrs(); got != nil {
		t.Errorf("on error = %v, want nil", got)
	}
}

func TestIfaceSet(t *testing.T) {
	var s ifaceSet
	if !s.includes("eth0") {
		t.Error("empty set should include every interface")
	}
	s.add("eth1")
	if s.includes("eth0") || !s.includes("eth1") {
		t.Errorf("{eth1}: %+v", s)
	}
	s.add("")
	if !s.includes("eth0") {
		t.Errorf("after every: %+v", s)
	}
}

// specific returns the scope of allow rules from these addresses.
func specific(addrs ...string) remoteScope {
	var s remoteScope
	s.widen(remoteSpecific, addrs...)
	return s
}

func TestReportedScope(t *testing.T) {
	var many remoteScope
	for i := 0; i < 15; i++ {
		many.widen(remoteSpecific, fmt.Sprintf("10.0.%d.0/24", i))
	}
	tests := []struct {
		name   string
		res    firewallResult
		scope  string
		nAddrs int
	}{
		{"blocked", firewallResult{verdict: firewallBlocked}, "", 0},
		{"unknown", firewallResult{verdict: firewallUnknown}, "", 0},
		{"disabled is any", firewallResult{verdict: firewallDisabled}, remoteAny, 0},
		{"allowed without a scope", firewallResult{verdict: firewallAllowed}, remoteUnknown, 0},
		{"local subnet", firewallResult{verdict: firewallAllowed, scope: remoteScope{kind: remoteLocalSubnet}}, remoteLocalSubnet, 0},
		{"specific capped at 10", firewallResult{verdict: firewallAllowed, scope: many}, remoteSpecific, maxRemoteAddresses},
		{"0.0.0.0/0 is any", firewallResult{verdict: firewallAllowed, scope: specific("10.0.0.0/8", "0.0.0.0/0")}, remoteAny, 0},
		{"::/0 is any", firewallResult{verdict: firewallAllowed, scope: specific("::/0")}, remoteAny, 0},
		{"0.0.0.0 alone is one address", firewallResult{verdict: firewallAllowed, scope: specific("0.0.0.0")}, remoteSpecific, 1},
	}
	for _, tt := range tests {
		scope, addrs := reportedScope(tt.res)
		if scope != tt.scope || len(addrs) != tt.nAddrs {
			t.Errorf("%s: %q, %d addresses; want %q, %d", tt.name, scope, len(addrs), tt.scope, tt.nAddrs)
		}
	}
}

func TestRemoteScope_WidestWins(t *testing.T) {
	var s remoteScope
	s.widen(remoteSpecific, "10.0.0.0/8")
	s.widen(remoteLocalSubnet)
	if s.kind != remoteLocalSubnet {
		t.Errorf("specific + local_subnet = %q", s.kind)
	}
	s.widen(remoteAny)
	s.widen(remoteSpecific, "10.0.0.0/8")
	if s.kind != remoteAny || !slices.Equal(s.addrs, []string{"10.0.0.0/8"}) {
		t.Errorf("after any: %+v", s)
	}
}

func TestSummarizeNetworkExposureLevel_Tiers(t *testing.T) {
	smb := func(fw, scope string, public bool, profiles ...string) shared.RiskyService {
		return shared.RiskyService{Name: "SMB", Port: 445, Protocol: "tcp", Firewall: fw, RemoteScope: scope, OnPublicAddress: public, ReachableProfiles: profiles}
	}
	tests := []struct {
		name    string
		svc     shared.RiskyService
		level   string
		recPart string
	}{
		{"any on a public address", smb(firewallAllowed, remoteAny, true, "Public"), "Critical", "SMB (445/tcp) on the Public network: allowed in from any address, on a public IP address"},
		{"firewall off on a public address", smb(firewallDisabled, remoteAny, true), "Critical", "public IP"},
		{"any on a private address", smb(firewallAllowed, remoteAny, false), "High", "allowed in from any address."},
		{"unknown scope on a public address", smb(firewallAllowed, remoteUnknown, true), "High", "couldn't verify"},
		{"old agent payload (no scope)", smb(firewallAllowed, "", false), "High", "couldn't verify"},
		{"unknown verdict", smb(firewallUnknown, "", true), "High", "couldn't verify"},
		{"local subnet only, even on a public address", smb(firewallAllowed, remoteLocalSubnet, true), "Medium", "only from the local subnet"},
		{"specific addresses", smb(firewallAllowed, remoteSpecific, false), "Medium", "listed addresses"},
		{"blocked", smb(firewallBlocked, "", true), "Medium", "host firewall blocks"},
	}
	for _, tt := range tests {
		level, recs := summarizeNetworkExposureLevel(shared.NetworkExposureAccessInfo{RiskyServices: []shared.RiskyService{tt.svc}})
		if level != tt.level || len(recs) != 1 || !strings.Contains(recs[0], tt.recPart) {
			t.Errorf("%s: level = %q, recs = %q; want %q containing %q", tt.name, level, recs, tt.level, tt.recPart)
		}
	}

	// A service let in from the local subnet on one socket and from any
	// address on another is listed once, under the wider exposure.
	level, recs := summarizeNetworkExposureLevel(shared.NetworkExposureAccessInfo{RiskyServices: []shared.RiskyService{
		smb(firewallAllowed, remoteLocalSubnet, false), smb(firewallAllowed, remoteAny, false),
		{Name: "RDP", Port: 3389, Protocol: "tcp", Firewall: firewallAllowed, RemoteScope: remoteSpecific},
	}})
	if level != "High" || len(recs) != 2 || !strings.Contains(recs[0], "SMB") || !strings.Contains(recs[1], "RDP") || strings.Contains(recs[1], "SMB") {
		t.Errorf("mixed: level = %q, recs = %q", level, recs)
	}

	// Two sockets of one service, let in on networks of different profiles,
	// are one entry naming both profiles.
	_, recs = summarizeNetworkExposureLevel(shared.NetworkExposureAccessInfo{RiskyServices: []shared.RiskyService{
		smb(firewallAllowed, remoteAny, false, "Private"), smb(firewallAllowed, remoteAny, false, "Public"),
		smb(firewallAllowed, remoteSpecific, false, "Domain"),
	}})
	if len(recs) != 1 || strings.Count(recs[0], "SMB") != 1 || !strings.Contains(recs[0], "on the Private/Public network") {
		t.Errorf("one service on two networks: recs = %q", recs)
	}
}

func TestComputePostureScore_CriticalExposureCostsPoint(t *testing.T) {
	var fw shared.FirewallSecurityInfo
	var enc shared.DeviceEncryptionInfo
	var id shared.IdentityAccessControlInfo
	if got := computePostureScore(fw, enc, id, postureRatings{exposure: "Critical"}); got != 0 {
		t.Errorf("score = %d, want 0", got)
	}
}
