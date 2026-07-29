package devicectx

import (
	"net"
	"path"
	"strings"

	"sentinelgo/internal/epm"
)

// networkResult is what collectNetworkReal produces for provider.go's
// collectNetwork to fold into the "network" source of the shared snapshot.
type networkResult struct {
	networkType      string
	ssid             string
	vpnActive        epm.Tri
	corporateNetwork epm.Tri
	dnsSuffixes      []string
	gateways         []string

	err error
}

// defaultVPNAdapterPatterns is used when a bundle's Defaults.VPNAdapterPatterns
// is empty — the common cross-platform VPN interface naming conventions
// (OpenVPN/WireGuard tunnels, PPP links, and anything an admin simply named
// with "vpn" in it). A bundle can override this entirely; it is not merged
// with the bundle's list.
var defaultVPNAdapterPatterns = []string{"tun*", "tap*", "wg*", "utun*", "ppp*", "*vpn*"}

// dnsSuffixesFn is a platform seam: network_unix.go (linux+darwin) reads
// /etc/resolv.conf; network_windows.go reads the Tcpip\Parameters registry
// key. Both are cheap, no-subprocess reads.
var dnsSuffixesFn = func() []string { return nil }

// gatewayIPsFn is deliberately left as a no-op stub across all three
// platforms in this pass: reading the actual default-gateway IP (and, for
// CorporateGatewayMACs matching, its MAC via an ARP-table read) is
// meaningfully more platform-specific plumbing than the DNS-suffix and CIDR
// signals below, for a field (ContextSnapshot.Gateways) that no Matcher
// currently reads — no ConditionKind in condition.go covers it, so it is
// purely informational/audit context today. Documented, accepted scope
// reduction for this pass, in the same spirit as skipping netwatch's
// event-driven invalidation: CorporateGatewayMACs stays an unused Defaults
// field until a later pass adds gateway/ARP collection, and
// CorporateNetwork classification below relies on CIDR + DNS suffix alone,
// which are both real, working signals.
var gatewayIPsFn = func() []string { return nil }

// collectNetworkReal enumerates active network interfaces and classifies
// them against defaults — see bundle.go's Defaults and the plan's
// "declarative, not heuristic" design: CorporateNetwork/VPNActive are only
// ever TriTrue/TriFalse relative to admin-configured patterns/CIDRs/suffixes,
// never guessed.
func collectNetworkReal(defaults epm.Defaults) networkResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return networkResult{err: err}
	}

	var active []net.Interface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		active = append(active, ifc)
	}

	vpnPatterns := defaults.VPNAdapterPatterns
	if len(vpnPatterns) == 0 {
		vpnPatterns = defaultVPNAdapterPatterns
	}

	res := networkResult{
		networkType: classifyNetworkType(active),
		vpnActive:   classifyByNamePatterns(active, vpnPatterns),
		dnsSuffixes: dnsSuffixesFn(),
		gateways:    gatewayIPsFn(),
	}
	res.corporateNetwork = classifyCorporateNetwork(collectInterfaceIPs(active), defaults, res.dnsSuffixes)
	return res
}

// collectInterfaceIPs resolves each active interface's addresses up front
// via the interfaceAddrsFn seam, so the pure classification logic below
// (classifyCorporateNetwork) never itself calls the OS — it only ever sees
// plain data, which is what makes it unit-testable without a live interface
// table (net.Interface.Addrs() looks addresses up by OS interface index, so
// a synthetic net.Interface{} literal in a test cannot satisfy it directly).
func collectInterfaceIPs(active []net.Interface) []net.IP {
	var ips []net.IP
	for _, ifc := range active {
		addrs, err := interfaceAddrsFn(ifc)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				ips = append(ips, ipNet.IP)
			}
		}
	}
	return ips
}

// interfaceAddrsFn is a seam over net.Interface.Addrs for testability.
var interfaceAddrsFn = func(ifc net.Interface) ([]net.Addr, error) { return ifc.Addrs() }

// interfaceNamePatterns classifies by well-known adapter naming conventions
// across Windows/Linux/macOS. This is a heuristic (unlike the declarative
// VPN/corporate-network checks below) because there is no cross-platform,
// subprocess-free way to ask "is this Wi-Fi or Ethernet" — the alternative
// (netsh/nmcli/networksetup subprocesses) is exactly the per-platform cost
// this package's cheap 60s-cadence tier is meant to avoid. A wrong
// classification here only affects CondNetworkType, which is not a
// verdict-family fail-closed condition on its own (see matchers_context.go);
// worst case a rule conditioning on network_type doesn't match when it
// plausibly should, which is the same safe-by-default direction as Unknown.
var (
	wiredPrefixes    = []string{"eth", "en", "ethernet"}
	wifiPrefixes     = []string{"wlan", "wl", "wi-fi", "wifi", "airport"}
	cellularPrefixes = []string{"wwan", "rmnet", "pdp", "cellular"}
)

func classifyNetworkType(active []net.Interface) string {
	if best := firstMatchingPrefix(active, wifiPrefixes); best != "" {
		return "wifi"
	}
	if best := firstMatchingPrefix(active, cellularPrefixes); best != "" {
		return "cellular"
	}
	if best := firstMatchingPrefix(active, wiredPrefixes); best != "" {
		return "wired"
	}
	return "unknown"
}

func firstMatchingPrefix(active []net.Interface, prefixes []string) string {
	for _, ifc := range active {
		lower := strings.ToLower(ifc.Name)
		for _, p := range prefixes {
			if strings.HasPrefix(lower, p) {
				return ifc.Name
			}
		}
	}
	return ""
}

// classifyByNamePatterns reports TriTrue if any active interface name
// matches one of patterns (case-insensitive glob, per path.Match), TriFalse
// if enumeration succeeded and none matched, TriUnknown only were
// enumeration itself to fail (handled by the caller before this is reached).
func classifyByNamePatterns(active []net.Interface, patterns []string) epm.Tri {
	for _, ifc := range active {
		lower := strings.ToLower(ifc.Name)
		for _, pat := range patterns {
			if ok, err := path.Match(strings.ToLower(pat), lower); err == nil && ok {
				return epm.TriTrue
			}
		}
	}
	return epm.TriFalse
}

// classifyCorporateNetwork reports TriTrue iff one of ips falls in one of
// Defaults.CorporateCIDRs, or a collected DNS suffix matches one of
// Defaults.CorporateDNSSuffixes. TriUnknown when the tenant has configured
// neither signal — "zero guessing": there is nothing to compare against,
// which is the same posture as no ContextProvider wired at all (see
// WithDefaults's doc comment in provider.go).
func classifyCorporateNetwork(ips []net.IP, defaults epm.Defaults, suffixes []string) epm.Tri {
	if len(defaults.CorporateCIDRs) == 0 && len(defaults.CorporateDNSSuffixes) == 0 {
		return epm.TriUnknown
	}

	var nets []*net.IPNet
	for _, cidr := range defaults.CorporateCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	for _, ip := range ips {
		for _, n := range nets {
			if n.Contains(ip) {
				return epm.TriTrue
			}
		}
	}

	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(suffix), "."))
		if suffix == "" {
			continue
		}
		for _, want := range defaults.CorporateDNSSuffixes {
			if strings.EqualFold(strings.TrimSuffix(want, "."), suffix) {
				return epm.TriTrue
			}
		}
	}

	return epm.TriFalse
}
