package routes

import (
	"strconv"
	"strings"
)

// This file holds every parsing and normalisation rule, deliberately free of
// build tags so all of it is unit-tested on every platform. The `_linux.go`,
// `_darwin.go` and `_windows.go` files only invoke the platform mechanism and
// hand the raw output here. That split is what makes a Linux parsing bug
// catchable from a Windows workstation.

// routeSources is the normalised vocabulary for Route.Source.
//
// Kept small on purpose: an operator wants to know whether a route was
// configured, learned or is a kernel artefact. Anything not in this map is
// dropped rather than passed through, so no platform can widen the vocabulary
// by accident and no unbounded token from command output reaches the wire.
var routeSources = map[string]string{
	"kernel": "kernel",
	"static": "static",
	"dhcp":   "dhcp",
	"ra":     "ra",
	"local":  "local",
	"boot":   "static",
	"bgp":    "bgp",
	"ospf":   "ospf",
	"rip":    "rip",
	"bird":   "bgp",
	"zebra":  "bgp",
	"babel":  "babel",
}

// normalizeSource maps a platform's own word for route provenance onto the
// vocabulary above, returning "" for anything unrecognised.
func normalizeSource(raw string) string {
	return routeSources[strings.ToLower(strings.TrimSpace(raw))]
}

// defaultDestination is the zero-length prefix for a family. Every platform
// prints the default route as the word "default"; the wire format always
// carries the real prefix so a consumer never has to know that.
func defaultDestination(family string) string {
	if family == FamilyIPv6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// normalizeDestination converts a platform's destination token into CIDR form.
//
// It handles the three shapes seen in practice:
//   - "default"            → the family's zero-length prefix
//   - "10.0.0.0/8", "::/0" → already CIDR, returned as-is
//   - "127.0.0.1", "::1"   → a bare host address, given its full-length prefix
//
// It also handles macOS's abbreviated network form ("192.168.1" meaning
// 192.168.1.0/24), which is netstat's own shorthand and not valid CIDR.
func normalizeDestination(raw, family string) string {
	d := strings.TrimSpace(raw)
	if d == "" {
		return ""
	}
	if strings.EqualFold(d, "default") {
		return defaultDestination(family)
	}

	// Strip a scope suffix such as "fe80::%utun0" — the zone is a property of
	// the interface, which is carried in its own field.
	if i := strings.Index(d, "%"); i >= 0 {
		if j := strings.Index(d, "/"); j > i {
			d = d[:i] + d[j:]
		} else {
			d = d[:i]
		}
	}

	if strings.Contains(d, "/") {
		return d
	}

	if family == FamilyIPv6 || strings.Contains(d, ":") {
		return d + "/128"
	}

	// IPv4 without a prefix. netstat on macOS abbreviates a network by
	// omitting trailing zero octets, so the octet count is the prefix length:
	// "127" is 127.0.0.0/8 and "192.168.1" is 192.168.1.0/24. A full four
	// octets is a host route.
	parts := strings.Split(d, ".")
	octets := len(parts)
	switch octets {
	case 4:
		return d + "/32"
	case 1, 2, 3:
		for len(parts) < 4 {
			parts = append(parts, "0")
		}
		return strings.Join(parts, ".") + "/" + strconv.Itoa(octets*8)
	default:
		return ""
	}
}

// ── Linux: `ip route show` / `ip -6 route show` ──────────────────────────────

// parseIPRoute parses iproute2's text output for one address family.
//
// The format is a destination token followed by key/value pairs:
//
//	default via 192.168.1.1 dev wlan0 proto dhcp metric 600
//	10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.2 metric 50
//	default via fe80::1 dev eth0 proto ra metric 1024 expires 1793sec pref medium
//
// Only the keys this collector models are read. `expires`, `pref`, `hoplimit`,
// `scope`, `src`, `error` and the rest are ignored — `expires` in particular
// counts down on every read, and capturing it would make a static IPv6 default
// route change its fingerprint on every cycle.
//
// Text output is used rather than `ip -json route`: the JSON flag needs
// iproute2 4.15+ (2018) and is still absent from some minimal and older
// enterprise images, whereas this text format has been stable for far longer.
func parseIPRoute(out, family string) []Route {
	var routes []Route

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}

		// Continuation lines of a multipath route ("nexthop via ... dev ...")
		// describe an additional hop for the preceding destination. They are
		// skipped rather than mis-parsed as a route with no destination.
		if fields[0] == "nexthop" {
			continue
		}
		// Cached entries are transient by definition.
		if fields[0] == "cache" || fields[0] == "broadcast" || fields[0] == "unreachable" {
			continue
		}

		r := Route{
			Family:      family,
			Destination: normalizeDestination(fields[0], family),
		}
		if r.Destination == "" {
			continue
		}

		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					r.Gateway = stripZone(fields[i+1])
					i++
				}
			case "dev":
				if i+1 < len(fields) {
					r.Interface = fields[i+1]
					i++
				}
			case "proto":
				if i+1 < len(fields) {
					r.Source = normalizeSource(fields[i+1])
					i++
				}
			case "metric":
				if i+1 < len(fields) {
					if n, err := strconv.Atoi(fields[i+1]); err == nil {
						m := n
						r.Metric = &m
					}
					i++
				}
			}
		}
		routes = append(routes, r)
	}
	return routes
}

// stripZone removes an IPv6 scope suffix from an address ("fe80::1%eth0").
func stripZone(addr string) string {
	if i := strings.Index(addr, "%"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// ── macOS: `netstat -rn` ─────────────────────────────────────────────────────

// parseNetstatRoutes parses BSD netstat's routing table.
//
// The output has two sections, each with its own header row:
//
//	Internet:
//	Destination        Gateway            Flags        Netif Expire
//	default            192.168.1.1        UGScg          en0
//	192.168.1          link#4             UCS            en0      !
//
//	Internet6:
//	Destination          Gateway           Flags        Netif Expire
//	default              fe80::%utun0      UGcI         utun0
//
// Three BSD-isms are handled: the "Internet6" header switches the family; a
// gateway of "link#N" means the route is on-link and has no next hop (reported
// as an empty Gateway, which is information rather than a failed read); and the
// Expire column is ignored, being a countdown that changes on every read.
//
// netstat states no route provenance at all, so Source is left empty on macOS
// rather than guessed from the flags — "UGSc" does not distinguish a static
// route from a DHCP-installed one.
func parseNetstatRoutes(out string) []Route {
	var routes []Route
	family := FamilyIPv4

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "Internet6"):
			family = FamilyIPv6
			continue
		case strings.HasPrefix(trimmed, "Internet"):
			family = FamilyIPv4
			continue
		case strings.HasPrefix(trimmed, "Routing tables"):
			continue
		case strings.HasPrefix(trimmed, "Destination"):
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}

		r := Route{
			Family:      family,
			Destination: normalizeDestination(fields[0], family),
			Gateway:     normalizeBSDGateway(fields[1]),
		}
		if r.Destination == "" {
			continue
		}
		// Column order is Destination, Gateway, Flags, Netif [, Expire].
		if len(fields) >= 4 {
			r.Interface = fields[3]
		}
		routes = append(routes, r)
	}
	return routes
}

// normalizeBSDGateway turns BSD's on-link markers into an empty next hop.
//
// "link#4" and a bare MAC address both mean "directly connected on this
// interface"; neither is a next-hop address, and reporting them as one would
// put a value in Gateway that no consumer could route on.
func normalizeBSDGateway(raw string) string {
	g := strings.TrimSpace(raw)
	if g == "" || strings.HasPrefix(g, "link#") {
		return ""
	}
	// A MAC address in the gateway column is an on-link ARP entry.
	if strings.Count(g, ":") == 5 && !strings.Contains(g, "::") {
		return ""
	}
	return stripZone(g)
}

// ── Windows: MSFT_NetRoute enums ─────────────────────────────────────────────

// windowsRouteProtocol maps the NL_ROUTE_PROTOCOL value MSFT_NetRoute reports
// onto the normalised Source vocabulary.
//
// The values follow the MIB_IPFORWARD_PROTO enumeration. NetMgmt (3) is what
// Windows records for a route configured administratively, which is what an
// operator means by "static".
func windowsRouteProtocol(proto uint16) string {
	switch proto {
	case 2:
		return "local"
	case 3:
		return "static"
	case 8:
		return "rip"
	case 13:
		return "ospf"
	case 14:
		return "bgp"
	case 19:
		return "dhcp"
	default:
		// 1 (Other) and the routing protocols this agent does not model fall
		// through to "unstated" rather than being invented.
		return ""
	}
}

// windowsAddressFamily maps the Win32 AF_* constant MSFT_NetRoute reports onto
// the Family vocabulary. 2 is AF_INET, 23 is AF_INET6.
func windowsAddressFamily(af uint16) string {
	if af == 23 {
		return FamilyIPv6
	}
	return FamilyIPv4
}

// normalizeWindowsNextHop turns Windows's on-link next-hop placeholders into an
// empty gateway.
//
// MSFT_NetRoute reports a directly-connected route's NextHop as the unspecified
// address for its family ("0.0.0.0" or "::") rather than omitting it. Carrying
// that straight through would put a non-routable address in Gateway and make
// on-link routes indistinguishable from a genuine default-via-0.0.0.0
// misconfiguration.
func normalizeWindowsNextHop(raw string) string {
	h := strings.TrimSpace(raw)
	switch h {
	case "", "0.0.0.0", "::":
		return ""
	default:
		return stripZone(h)
	}
}
