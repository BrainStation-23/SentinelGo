package security

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

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
		verdict, level string
	}{
		{firewallAllowed, "High"},
		{firewallDisabled, "High"},
		{firewallUnknown, "High"},
		{firewallBlocked, "Medium"},
	} {
		check := func(shared.ListeningPort) (string, []string) { return tt.verdict, nil }
		info := analyzeNetworkExposure(ports, check)
		if !slices.Equal(info.OpenAdministrativePorts, []uint16{445}) {
			t.Errorf("%s: OpenAdministrativePorts = %v, want [445]", tt.verdict, info.OpenAdministrativePorts)
		}
		want := shared.RiskyService{Name: "SMB", Port: 445, Protocol: "tcp", Address: "0.0.0.0", Scope: scopeAll, ProcessName: "System", Firewall: tt.verdict}
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
	info := analyzeNetworkExposure(ports, func(p shared.ListeningPort) (string, []string) {
		if p.Port == 22 {
			return firewallAllowed, []string{"Public"}
		}
		return firewallBlocked, nil
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
