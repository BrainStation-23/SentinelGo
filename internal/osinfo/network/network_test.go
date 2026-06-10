package network

import (
	"testing"

	psnet "github.com/shirou/gopsutil/v3/net"
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
