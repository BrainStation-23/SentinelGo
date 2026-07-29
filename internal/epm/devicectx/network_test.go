package devicectx

import (
	"net"
	"testing"

	"sentinelgo/internal/epm"
)

func iface(name string) net.Interface {
	return net.Interface{Name: name, Flags: net.FlagUp}
}

func TestClassifyNetworkType(t *testing.T) {
	cases := []struct {
		name string
		ifs  []net.Interface
		want string
	}{
		{"empty", nil, "unknown"},
		{"wired", []net.Interface{iface("eth0")}, "wired"},
		{"windows ethernet", []net.Interface{iface("Ethernet")}, "wired"},
		{"wifi", []net.Interface{iface("wlan0")}, "wifi"},
		{"macos wifi", []net.Interface{iface("en0")}, "wired"}, // en* is treated as wired per the documented heuristic limitation
		{"cellular", []net.Interface{iface("wwan0")}, "cellular"},
		{"wifi wins over wired when both present", []net.Interface{iface("eth0"), iface("wlan0")}, "wifi"},
		{"unrecognized", []net.Interface{iface("utun0")}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNetworkType(tc.ifs); got != tc.want {
				t.Errorf("classifyNetworkType(%v) = %q, want %q", tc.ifs, got, tc.want)
			}
		})
	}
}

func TestClassifyByNamePatterns(t *testing.T) {
	patterns := defaultVPNAdapterPatterns
	cases := []struct {
		name string
		ifs  []net.Interface
		want epm.Tri
	}{
		{"no interfaces", nil, epm.TriFalse},
		{"no match", []net.Interface{iface("eth0")}, epm.TriFalse},
		{"tun match", []net.Interface{iface("tun0")}, epm.TriTrue},
		{"utun match (macOS)", []net.Interface{iface("utun3")}, epm.TriTrue},
		{"wildcard vpn match", []net.Interface{iface("MyCorpVPNAdapter")}, epm.TriTrue},
		{"wireguard match", []net.Interface{iface("wg0")}, epm.TriTrue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyByNamePatterns(tc.ifs, patterns); got != tc.want {
				t.Errorf("classifyByNamePatterns(%v) = %v, want %v", tc.ifs, got, tc.want)
			}
		})
	}
}

func TestClassifyCorporateNetwork(t *testing.T) {
	t.Run("no defaults configured is Unknown", func(t *testing.T) {
		got := classifyCorporateNetwork(nil, epm.Defaults{}, nil)
		if got != epm.TriUnknown {
			t.Errorf("got %v, want TriUnknown", got)
		}
	})

	t.Run("CIDR match", func(t *testing.T) {
		defaults := epm.Defaults{CorporateCIDRs: []string{"10.0.0.0/8"}}
		ips := []net.IP{net.ParseIP("10.1.2.3")}
		got := classifyCorporateNetwork(ips, defaults, nil)
		if got != epm.TriTrue {
			t.Errorf("got %v, want TriTrue", got)
		}
	})

	t.Run("CIDR configured but no IP matches is False", func(t *testing.T) {
		defaults := epm.Defaults{CorporateCIDRs: []string{"10.0.0.0/8"}}
		ips := []net.IP{net.ParseIP("192.168.1.5")}
		got := classifyCorporateNetwork(ips, defaults, nil)
		if got != epm.TriFalse {
			t.Errorf("got %v, want TriFalse", got)
		}
	})

	t.Run("DNS suffix match", func(t *testing.T) {
		defaults := epm.Defaults{CorporateDNSSuffixes: []string{"corp.example.com"}}
		got := classifyCorporateNetwork(nil, defaults, []string{"corp.example.com"})
		if got != epm.TriTrue {
			t.Errorf("got %v, want TriTrue", got)
		}
	})

	t.Run("DNS suffix match is case-insensitive and trailing-dot-tolerant", func(t *testing.T) {
		defaults := epm.Defaults{CorporateDNSSuffixes: []string{"Corp.Example.com."}}
		got := classifyCorporateNetwork(nil, defaults, []string{"corp.example.com"})
		if got != epm.TriTrue {
			t.Errorf("got %v, want TriTrue", got)
		}
	})

	t.Run("DNS suffix configured but no match is False", func(t *testing.T) {
		defaults := epm.Defaults{CorporateDNSSuffixes: []string{"corp.example.com"}}
		got := classifyCorporateNetwork(nil, defaults, []string{"home.lan"})
		if got != epm.TriFalse {
			t.Errorf("got %v, want TriFalse", got)
		}
	})
}

func TestCollectInterfaceIPs_UsesAddrsSeam(t *testing.T) {
	orig := interfaceAddrsFn
	defer func() { interfaceAddrsFn = orig }()

	_, corpNet, _ := net.ParseCIDR("10.0.0.0/8")
	interfaceAddrsFn = func(ifc net.Interface) ([]net.Addr, error) {
		if ifc.Name == "eth0" {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("10.5.5.5"), Mask: corpNet.Mask}}, nil
		}
		return nil, nil
	}

	ips := collectInterfaceIPs([]net.Interface{iface("eth0"), iface("wlan0")})
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.5.5.5")) {
		t.Errorf("collectInterfaceIPs() = %v, want [10.5.5.5]", ips)
	}
}

func TestCollectNetworkReal_UsesSeams(t *testing.T) {
	origDNS, origGW := dnsSuffixesFn, gatewayIPsFn
	defer func() { dnsSuffixesFn, gatewayIPsFn = origDNS, origGW }()

	dnsSuffixesFn = func() []string { return []string{"corp.example.com"} }
	gatewayIPsFn = func() []string { return []string{"10.0.0.1"} }

	res := collectNetworkReal(epm.Defaults{})
	if res.err != nil {
		t.Fatalf("collectNetworkReal() error = %v", res.err)
	}
	if len(res.dnsSuffixes) != 1 || res.dnsSuffixes[0] != "corp.example.com" {
		t.Errorf("dnsSuffixes = %v, want [corp.example.com]", res.dnsSuffixes)
	}
	if len(res.gateways) != 1 || res.gateways[0] != "10.0.0.1" {
		t.Errorf("gateways = %v, want [10.0.0.1]", res.gateways)
	}
}
