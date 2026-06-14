package network

import (
	stdnet "net"
	"testing"

	psnet "github.com/shirou/gopsutil/v4/net"
)

func TestHasFlag(t *testing.T) {
	iface := psnet.InterfaceStat{Flags: []string{"up", "broadcast", "multicast"}}
	tests := []struct {
		flag string
		want bool
	}{
		{"up", true},
		{"UP", true},
		{"broadcast", true},
		{"loopback", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			if got := hasFlag(iface, tc.flag); got != tc.want {
				t.Errorf("hasFlag(%q) = %v, want %v", tc.flag, got, tc.want)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		want  bool
	}{
		{"loopback iface", []string{"up", "loopback"}, true},
		{"LOOPBACK uppercase", []string{"LOOPBACK"}, true},
		{"regular iface", []string{"up", "broadcast"}, false},
		{"no flags", []string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iface := psnet.InterfaceStat{Flags: tc.flags}
			if got := isLoopback(iface); got != tc.want {
				t.Errorf("isLoopback() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetPrimaryMACAddress(t *testing.T) {
	tests := []struct {
		name   string
		ifaces []psnet.InterfaceStat
		want   string
	}{
		{
			name: "picks first non-zero MAC",
			ifaces: []psnet.InterfaceStat{
				{Name: "lo", HardwareAddr: "00:00:00:00:00:00"},
				{Name: "eth0", HardwareAddr: "aa:bb:cc:dd:ee:ff"},
				{Name: "wlan0", HardwareAddr: "11:22:33:44:55:66"},
			},
			want: "aa:bb:cc:dd:ee:ff",
		},
		{
			name: "all zero MACs returns empty",
			ifaces: []psnet.InterfaceStat{
				{Name: "lo", HardwareAddr: "00:00:00:00:00:00"},
			},
			want: "",
		},
		{
			name:   "empty slice returns empty",
			ifaces: []psnet.InterfaceStat{},
			want:   "",
		},
		{
			name: "skips zero-prefix MAC",
			ifaces: []psnet.InterfaceStat{
				{Name: "lo", HardwareAddr: "00:00:00:ab:cd:ef"},
				{Name: "eth0", HardwareAddr: "de:ad:be:ef:00:01"},
			},
			want: "de:ad:be:ef:00:01",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GetPrimaryMACAddress(tc.ifaces); got != tc.want {
				t.Errorf("GetPrimaryMACAddress() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── adapterStatus ─────────────────────────────────────────────────────────────

func TestAdapterStatus(t *testing.T) {
	if got := adapterStatus(true); got != "Up" {
		t.Errorf("adapterStatus(true) = %q, want \"Up\"", got)
	}
	if got := adapterStatus(false); got != "Down" {
		t.Errorf("adapterStatus(false) = %q, want \"Down\"", got)
	}
}

// ── parseAddresses ────────────────────────────────────────────────────────────

func TestParseAddresses_IPv4CIDR(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "192.168.1.100/24"},
	}
	ipv4s, ipv6s, hasRoutable := parseAddresses(addrs)
	if len(ipv4s) != 1 {
		t.Fatalf("expected 1 IPv4, got %d", len(ipv4s))
	}
	if ipv4s[0].Address != "192.168.1.100" {
		t.Errorf("IPv4 address = %q, want 192.168.1.100", ipv4s[0].Address)
	}
	if len(ipv6s) != 0 {
		t.Errorf("expected 0 IPv6, got %d", len(ipv6s))
	}
	if !hasRoutable {
		t.Error("expected hasRoutableIPv4 = true for 192.168.1.100/24")
	}
}

func TestParseAddresses_IPv4Loopback(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "127.0.0.1/8"},
	}
	ipv4s, _, hasRoutable := parseAddresses(addrs)
	if len(ipv4s) != 1 {
		t.Fatalf("expected 1 IPv4 (loopback), got %d", len(ipv4s))
	}
	if hasRoutable {
		t.Error("expected hasRoutableIPv4 = false for loopback address")
	}
}

func TestParseAddresses_IPv6(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "2001:db8::1/64"},
	}
	ipv4s, ipv6s, _ := parseAddresses(addrs)
	if len(ipv4s) != 0 {
		t.Errorf("expected 0 IPv4, got %d", len(ipv4s))
	}
	if len(ipv6s) != 1 {
		t.Fatalf("expected 1 IPv6, got %d", len(ipv6s))
	}
	if ipv6s[0].PrefixLen != 64 {
		t.Errorf("IPv6 PrefixLen = %d, want 64", ipv6s[0].PrefixLen)
	}
}

func TestParseAddresses_PlainIP(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "10.0.0.5"}, // no CIDR notation
	}
	ipv4s, _, hasRoutable := parseAddresses(addrs)
	if len(ipv4s) != 1 {
		t.Fatalf("expected 1 IPv4 from plain IP, got %d", len(ipv4s))
	}
	if !hasRoutable {
		t.Error("expected hasRoutableIPv4 = true for 10.0.0.5")
	}
}

func TestParseAddresses_Invalid(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "not-an-ip"},
	}
	ipv4s, ipv6s, _ := parseAddresses(addrs)
	if len(ipv4s) != 0 || len(ipv6s) != 0 {
		t.Error("expected no addresses for invalid input")
	}
}

func TestParseAddresses_Empty(t *testing.T) {
	ipv4s, ipv6s, hasRoutable := parseAddresses(nil)
	if len(ipv4s) != 0 || len(ipv6s) != 0 || hasRoutable {
		t.Error("expected empty results for nil input")
	}
}

// ── makeIPv4Entry / makeIPv6Entry ─────────────────────────────────────────────

func TestMakeIPv4Entry_WithSubnet(t *testing.T) {
	ip := stdnet.ParseIP("192.168.1.50")
	_, ipNet, _ := stdnet.ParseCIDR("192.168.1.0/24")

	entry := makeIPv4Entry(ip, ipNet)
	if entry.Address != "192.168.1.50" {
		t.Errorf("Address = %q, want 192.168.1.50", entry.Address)
	}
	if entry.SubnetMask == "" {
		t.Error("expected non-empty SubnetMask")
	}
	if entry.Subnet == "" {
		t.Error("expected non-empty Subnet")
	}
}

func TestMakeIPv4Entry_NilIPNet(t *testing.T) {
	ip := stdnet.ParseIP("10.0.0.1")
	entry := makeIPv4Entry(ip, nil)
	if entry.Address != "10.0.0.1" {
		t.Errorf("Address = %q, want 10.0.0.1", entry.Address)
	}
	// SubnetMask and Subnet remain zero-values when ipNet is nil
	if entry.SubnetMask != "" {
		t.Errorf("expected empty SubnetMask for nil ipNet, got %q", entry.SubnetMask)
	}
}

func TestMakeIPv6Entry_WithPrefix(t *testing.T) {
	ip := stdnet.ParseIP("2001:db8::1")
	_, ipNet, _ := stdnet.ParseCIDR("2001:db8::/32")

	entry := makeIPv6Entry(ip, ipNet)
	if entry.Address == "" {
		t.Error("expected non-empty Address")
	}
	if entry.PrefixLen != 32 {
		t.Errorf("PrefixLen = %d, want 32", entry.PrefixLen)
	}
}

func TestMakeIPv6Entry_NilIPNet(t *testing.T) {
	ip := stdnet.ParseIP("::1")
	entry := makeIPv6Entry(ip, nil)
	if entry.Address != "::1" {
		t.Errorf("Address = %q, want ::1", entry.Address)
	}
	if entry.PrefixLen != 0 {
		t.Errorf("expected PrefixLen 0 for nil ipNet, got %d", entry.PrefixLen)
	}
}

// ── TestGet_Integration ───────────────────────────────────────────────────────

// TestParseAddresses_IPv6Loopback verifies that the IPv6 loopback address (::1/128)
// is parsed as an IPv6 entry and not treated as a routable IPv4.
func TestParseAddresses_IPv6Loopback(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "::1/128"},
	}
	ipv4s, ipv6s, hasRoutable := parseAddresses(addrs)
	if len(ipv4s) != 0 {
		t.Errorf("expected 0 IPv4 for IPv6 loopback, got %d", len(ipv4s))
	}
	if len(ipv6s) != 1 {
		t.Errorf("expected 1 IPv6 for ::1/128, got %d", len(ipv6s))
	}
	if hasRoutable {
		t.Error("expected hasRoutableIPv4 = false for IPv6-only interface")
	}
}

// TestParseAddresses_Multiple verifies that a mixed list of IPv4 and IPv6
// addresses is split correctly.
func TestParseAddresses_Multiple(t *testing.T) {
	addrs := []psnet.InterfaceAddr{
		{Addr: "192.168.0.10/24"},
		{Addr: "2001:db8::2/64"},
	}
	ipv4s, ipv6s, hasRoutable := parseAddresses(addrs)
	if len(ipv4s) != 1 {
		t.Errorf("expected 1 IPv4, got %d", len(ipv4s))
	}
	if len(ipv6s) != 1 {
		t.Errorf("expected 1 IPv6, got %d", len(ipv6s))
	}
	if !hasRoutable {
		t.Error("expected hasRoutableIPv4 = true for 192.168.0.10/24")
	}
}

func TestGet_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network adapter collection in -short mode")
	}
	adapters := Get()
	if len(adapters) == 0 {
		t.Skip("no non-loopback adapters found; skipping")
	}
	for i, a := range adapters {
		if a.InterfaceName == "" {
			t.Errorf("adapter[%d]: InterfaceName is empty", i)
		}
		if a.AdapterType == "" {
			t.Errorf("adapter[%d] %s: AdapterType is empty", i, a.InterfaceName)
		}
		if a.Status == "" {
			t.Errorf("adapter[%d] %s: Status is empty", i, a.InterfaceName)
		}
		t.Logf("adapter[%d]: name=%s friendly=%s device=%s type=%s status=%s connected=%v mac=%s speed=%d gw=%s dns=%v wifi=%v",
			i, a.InterfaceName, a.FriendlyName, a.DeviceName, a.AdapterType, a.Status,
			a.IsConnected, a.MACAddress, a.SpeedMbps, a.DefaultGateway, a.DNSServers, a.WiFi)
	}
}
