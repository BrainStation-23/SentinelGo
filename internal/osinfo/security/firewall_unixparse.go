package security

// ufw, firewalld and macOS Application Firewall parsers (#221). No OS
// suffix so they are tested everywhere; firewall_linux.go and
// firewall_darwin.go call them.

import (
	"encoding/xml"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// portSpec is a port range for one protocol, or both when protocol is "".
type portSpec struct {
	protocol string
	from, to uint16
}

func (s portSpec) covers(p shared.ListeningPort) bool {
	return (s.protocol == "" || strings.EqualFold(s.protocol, p.Protocol)) && p.Port >= s.from && p.Port <= s.to
}

func anyCovers(specs []portSpec, p shared.ListeningPort) bool {
	for _, s := range specs {
		if s.covers(p) {
			return true
		}
	}
	return false
}

// parsePortList parses "22", "80,443/tcp", "5900:5906/tcp" (ufw, sep ":")
// or "5900-5906/tcp" (firewalld, sep "-"). ok is false for anything else,
// such as an application profile name.
func parsePortList(s, sep string) (specs []portSpec, ok bool) {
	list, proto, _ := strings.Cut(strings.TrimSpace(s), "/")
	proto = strings.ToLower(proto)
	if proto != "" && proto != "tcp" && proto != "udp" {
		return nil, false
	}
	for _, item := range strings.Split(list, ",") {
		lo, hi, ok := parsePortRange(item, sep)
		if !ok {
			return nil, false
		}
		specs = append(specs, portSpec{protocol: proto, from: lo, to: hi})
	}
	return specs, len(specs) > 0
}

// ── ufw ──────────────────────────────────────────────────────────────────────

// ufwRule is one inbound rule of `ufw status verbose`, in evaluation order.
type ufwRule struct {
	allPorts  bool       // "Anywhere": every port
	ports     []portSpec // when not allPorts and app == ""
	app       string     // application profile name
	action    string     // "allow", "limit", "deny" or "reject"
	anySource bool       // from "Anywhere"
	source    string     // the "From" address or prefix when not anySource
	family    int        // 4 or 6: ufw lists each address family's rules separately
	iface     string     // "on eth0": only traffic arriving on that interface
	dest      netip.Prefix
}

type ufwStatus struct {
	active          bool
	defaultIncoming string // "deny", "reject" or "allow"
	rules           []ufwRule
}

var (
	ufwColumns   = regexp.MustCompile(`\s{2,}`)
	ufwInterface = regexp.MustCompile(` on (\S+)$`)
	ufwDefault   = regexp.MustCompile(`(?i)default:\s*(\w+)\s*\(incoming\)`)
)

// parseUFWStatus parses `ufw status verbose`.
func parseUFWStatus(out string) ufwStatus {
	var st ufwStatus
	inRules := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r ")
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "status:"):
			st.active = strings.TrimSpace(strings.TrimPrefix(lower, "status:")) == "active"
		case ufwDefault.MatchString(line):
			st.defaultIncoming = strings.ToLower(ufwDefault.FindStringSubmatch(line)[1])
		case strings.HasPrefix(line, "--"):
			inRules = true
		case inRules && strings.TrimSpace(line) != "":
			if r, ok := parseUFWRule(line); ok {
				st.rules = append(st.rules, r)
			}
		}
	}
	return st
}

// ufwStrip removes the "(v6)" and "on <interface>" qualifiers from a
// column, returning the interface.
func ufwStrip(s string) (rest, iface string) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "(v6)", ""))
	if m := ufwInterface.FindStringSubmatch(s); m != nil {
		iface = m[1]
		s = strings.TrimSpace(strings.TrimSuffix(s, m[0]))
	}
	return s, iface
}

// parseUFWRule parses "To  Action  From", e.g. "22/tcp  ALLOW IN  Anywhere".
// Outbound and forwarding rules are skipped.
func parseUFWRule(line string) (ufwRule, bool) {
	cols := ufwColumns.Split(strings.TrimSpace(line), -1)
	if len(cols) < 3 {
		return ufwRule{}, false
	}
	actionWords := strings.Fields(strings.ToLower(cols[1]))
	if len(actionWords) == 0 || (len(actionWords) > 1 && actionWords[1] != "in") {
		return ufwRule{}, false
	}
	from, _ := ufwStrip(cols[2])
	to, iface := ufwStrip(cols[0])
	r := ufwRule{action: actionWords[0], anySource: from == "Anywhere", iface: iface, family: 4}
	if !r.anySource {
		r.source, _, _ = strings.Cut(from, " ")
	}
	if strings.Contains(cols[0], "(v6)") || strings.Contains(cols[2], "(v6)") {
		r.family = 6
	}
	if src, ok := parseAddressOrPrefix(from); ok {
		r.family = prefixFamily(src)
	}

	// The destination may start with an address: "10.0.0.5 22/tcp".
	first, rest, found := strings.Cut(to, " ")
	if !found {
		first, rest = to, ""
	}
	if dest, ok := parseAddressOrPrefix(first); ok {
		r.dest, r.family, to = dest, prefixFamily(dest), strings.TrimSpace(rest)
	} else if first == "Anywhere" {
		to = strings.TrimSpace(rest)
	}
	switch specs, ok := parsePortList(to, ":"); {
	case to == "":
		r.allPorts = true
	case ok:
		r.ports = specs
	default:
		r.app = to
	}
	return r, true
}

// parseAddressOrPrefix parses "10.0.0.5" or "10.0.0.0/8" as a prefix.
func parseAddressOrPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func prefixFamily(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 4
	}
	return 6
}

// listenerFamilies returns the address families a socket accepts and, for
// a socket bound to one address, that address. A socket on "::" accepts IPv4
// too unless v6Only (Linux binds dual-stack by default); one whose address
// can't be parsed is treated as accepting both.
func listenerFamilies(addr string, v6Only bool) (families []int, bound netip.Addr) {
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(addr), "["), "]"))
	if err != nil {
		return []int{4, 6}, netip.Addr{}
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified() && a.Is4():
		return []int{4}, netip.Addr{}
	case a.IsUnspecified() && v6Only:
		return []int{6}, netip.Addr{}
	case a.IsUnspecified():
		return []int{4, 6}, netip.Addr{}
	case a.Is4():
		return []int{4}, a.WithZone("")
	default:
		return []int{6}, a.WithZone("")
	}
}

// parseUFWAppProfiles reads ufw application profiles (the INI files in
// /etc/ufw/applications.d): "[OpenSSH]" sections with "ports=22/tcp" or
// "ports=137,138/udp|139,445/tcp".
func parseUFWAppProfiles(contents []string) map[string][]portSpec {
	apps := map[string][]portSpec{}
	for _, content := range contents {
		section := ""
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
				continue
			}
			key, val, ok := strings.Cut(line, "=")
			if ok && section != "" && strings.TrimSpace(key) == "ports" {
				apps[section] = append(apps[section], parseUFWAppPorts(val)...)
			}
		}
	}
	return apps
}

// parseUFWAppPorts parses a profile's ports value, "|"-separated groups.
func parseUFWAppPorts(val string) []portSpec {
	var specs []portSpec
	for _, group := range strings.Split(val, "|") {
		if s, ok := parsePortList(group, ":"); ok {
			specs = append(specs, s...)
		}
	}
	return specs
}

// ufwHost is what the ufw check needs to know about the host.
type ufwHost struct {
	// arrival lists the non-loopback interfaces that are up: the ways a
	// connection can come in. A deny on one interface decides only when it's
	// the only one. nil when unknown.
	arrival []string
	// v6Only reports whether a socket on "::" accepts IPv6 only. nil means
	// dual-stack, Linux's default.
	v6Only func(p shared.ListeningPort) bool
}

// newUFWHost builds the host context. A socket on "::" is IPv6-only when the
// same port also has an IPv4 wildcard socket (see v4WildcardPorts).
func newUFWHost(ports []shared.ListeningPort, arrival []string) ufwHost {
	return ufwHost{arrival: arrival, v6Only: v4WildcardPorts(ports)}
}

// check evaluates the rules separately for each address family the socket
// accepts, since ufw lists IPv4 and IPv6 rules separately; the socket is
// reachable when either family lets connections in. When one family allows
// and another is unknown, whom the unknown one lets in is unknown too.
func (st ufwStatus) check(apps map[string][]portSpec, host ufwHost) firewallCheck {
	return func(p shared.ListeningPort) firewallResult {
		families, bound := listenerFamilies(p.Address, host.v6Only != nil && host.v6Only(p))
		verdicts := make([]string, 0, len(families))
		var scope remoteScope
		var via ifaceSet
		for _, f := range families {
			verdict, s, v := st.checkFamily(apps, p, f, bound, host.arrival)
			verdicts = append(verdicts, verdict)
			scope.merge(s)
			for _, name := range v.names {
				via.add(name)
			}
			if v.every {
				via.add("")
			}
		}
		switch {
		case slices.Contains(verdicts, firewallAllowed):
			if slices.Contains(verdicts, firewallUnknown) {
				scope.widen(remoteUnknown)
				via.add("")
			}
			return firewallResult{verdict: firewallAllowed, scope: scope, via: via}
		case slices.Contains(verdicts, firewallUnknown):
			return firewallResult{verdict: firewallUnknown}
		default:
			return firewallResult{verdict: firewallBlocked}
		}
	}
}

// checkFamily evaluates one family's rules in order, as ufw does: the first
// rule matching a connection decides it. A deny decides for every connection
// only when it covers them all: from anywhere, on every interface
// connections can arrive on, to the socket's address. Narrower denies leave
// other traffic to later rules. Every allow rule before that point lets its
// sources in, so their scopes are collected: "Anywhere" is any, an address
// or prefix is specific; and the interfaces they're limited to. Rules naming
// an application profile that isn't installed make an otherwise blocked
// verdict unknown. When the port is allowed anyway, such an allow rule may
// let its sources in too: from Anywhere makes the scope unknown.
func (st ufwStatus) checkFamily(apps map[string][]portSpec, p shared.ListeningPort, family int, bound netip.Addr, arrival []string) (string, remoteScope, ifaceSet) {
	uncertain, allowed := false, false
	var scope, maybe remoteScope
	var via, maybeVia ifaceSet
	allowedResult := func() (string, remoteScope, ifaceSet) {
		if maybe.kind != "" {
			scope.merge(maybe)
			for _, name := range maybeVia.names {
				via.add(name)
			}
			if maybeVia.every {
				via.add("")
			}
		}
		return firewallAllowed, scope, via
	}
	for _, r := range st.rules {
		matches, known := r.coversPort(apps, p)
		if !known && r.reaches(family, bound) {
			uncertain = true
			if r.action == "allow" || r.action == "limit" {
				if r.anySource {
					maybe.widen(remoteUnknown)
				} else {
					maybe.widen(remoteSpecific, r.source)
				}
				maybeVia.add(r.iface)
			}
		}
		if !matches || !r.reaches(family, bound) {
			continue
		}
		switch r.action {
		case "allow", "limit":
			allowed = true
			via.add(r.iface)
			if r.anySource {
				scope.widen(remoteAny)
			} else {
				scope.widen(remoteSpecific, r.source)
			}
		case "deny", "reject":
			if r.blocksEverything(bound, arrival) {
				if allowed {
					return allowedResult()
				}
				return firewallBlocked, remoteScope{}, ifaceSet{}
			}
		}
	}
	if st.defaultIncoming == "allow" {
		scope.widen(remoteAny)
		via.add("")
		return allowedResult()
	}
	switch {
	case allowed:
		return allowedResult()
	case uncertain:
		return firewallUnknown, remoteScope{}, ifaceSet{}
	}
	return firewallBlocked, remoteScope{}, ifaceSet{}
}

// reaches reports whether the rule can apply to traffic for a socket of this
// family bound to bound (invalid for a wildcard socket): a rule for another
// family, or for a destination address the socket isn't bound to, can't.
func (r ufwRule) reaches(family int, bound netip.Addr) bool {
	return r.family == family && (!bound.IsValid() || !r.dest.IsValid() || r.dest.Contains(bound))
}

// blocksEverything reports whether a deny covers every connection to the
// socket: from anywhere, to every address it's bound to (a wildcard socket
// also gets traffic for other addresses), and on every interface a
// connection can arrive on. A deny on one interface covers them all only
// when it's the host's only arrival interface: Linux accepts a packet for
// any local address on any interface.
func (r ufwRule) blocksEverything(bound netip.Addr, arrival []string) bool {
	everyInterface := r.iface == "" || (len(arrival) == 1 && arrival[0] == r.iface)
	return r.anySource && everyInterface && (!r.dest.IsValid() || bound.IsValid())
}

// coversPort reports whether the rule's ports include p's. known is false
// for an application profile that isn't installed.
func (r ufwRule) coversPort(apps map[string][]portSpec, p shared.ListeningPort) (matches, known bool) {
	switch {
	case r.allPorts:
		return true, true
	case r.app != "":
		specs, ok := apps[r.app]
		return ok && anyCovers(specs, p), ok
	default:
		return anyCovers(r.ports, p), true
	}
}

// ── firewalld ────────────────────────────────────────────────────────────────

type firewalldZone struct {
	name       string
	active     bool
	isDefault  bool
	target     string
	services   []string
	ports      []portSpec
	richOpen   []richPortRule    // ports a rich rule accepts
	richSvcs   []richServiceRule // services a rich rule accepts
	sourceAll  []string          // sources a rich rule accepts everything from
	interfaces []string          // interfaces bound to the zone
	sources    []string          // source addresses bound to the zone
}

// richPortRule and richServiceRule are what an accepting rich rule opens,
// and the source it's limited to ("" for any).
type richPortRule struct {
	spec   portSpec
	source string
}

type richServiceRule struct {
	name   string
	source string
}

var (
	richPort    = regexp.MustCompile(`port port="([^"]+)" protocol="(tcp|udp)"`)
	richService = regexp.MustCompile(`service name="([^"]+)"`)
	richSource  = regexp.MustCompile(`source (?:address|ipset)="([^"]+)"`)
)

// parseFirewalldZones parses `firewall-cmd --list-all-zones`.
func parseFirewalldZones(out string) []firewalldZone {
	var zones []firewalldZone
	var cur *firewalldZone
	inRich := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r ")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, flags, _ := strings.Cut(line, " ")
			zones = append(zones, firewalldZone{
				name:      name,
				active:    strings.Contains(flags, "active"),
				isDefault: strings.Contains(flags, "default"),
			})
			cur = &zones[len(zones)-1]
			inRich = false
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		switch {
		case ok && !strings.HasPrefix(strings.TrimSpace(line), "rule "):
			inRich = key == "rich rules"
			cur.setField(key, val)
		case inRich:
			cur.addRichRule(strings.TrimSpace(line))
		}
	}
	return zones
}

// setField records one "key: value" line of a zone.
func (z *firewalldZone) setField(key, val string) {
	switch key {
	case "target":
		z.target = strings.TrimSpace(val)
	case "services":
		z.services = strings.Fields(val)
	case "interfaces":
		z.interfaces = strings.Fields(val)
	case "sources":
		z.sources = strings.Fields(val)
	case "ports":
		for _, f := range strings.Fields(val) {
			if specs, ok := parsePortList(f, "-"); ok {
				z.ports = append(z.ports, specs...)
			}
		}
	}
}

// addRichRule records what an accepting rich rule opens.
func (z *firewalldZone) addRichRule(rule string) {
	if !strings.HasSuffix(rule, " accept") && !strings.Contains(rule, " accept ") {
		return
	}
	// A "source NOT address" rule admits everyone but that source.
	source := ""
	if m := richSource.FindStringSubmatch(rule); m != nil && !strings.Contains(rule, "source NOT ") {
		source = m[1]
	}
	switch {
	case richPort.MatchString(rule):
		m := richPort.FindStringSubmatch(rule)
		if lo, hi, ok := parsePortRange(m[1], "-"); ok {
			z.richOpen = append(z.richOpen, richPortRule{spec: portSpec{protocol: m[2], from: lo, to: hi}, source: source})
		}
	case richService.MatchString(rule):
		z.richSvcs = append(z.richSvcs, richServiceRule{name: richService.FindStringSubmatch(rule)[1], source: source})
	case !strings.Contains(rule, " port ") && !strings.Contains(rule, " protocol ") && !strings.Contains(rule, "icmp"):
		z.sourceAll = append(z.sourceAll, source)
	}
}

// parseFirewalldService reads the ports of a firewalld service definition
// (/usr/lib/firewalld/services/<name>.xml).
func parseFirewalldService(data []byte) ([]portSpec, bool) {
	var svc struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			Port     string `xml:"port,attr"`
		} `xml:"port"`
	}
	if xml.Unmarshal(data, &svc) != nil {
		return nil, false
	}
	var specs []portSpec
	for _, p := range svc.Ports {
		proto := strings.ToLower(p.Protocol)
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if lo, hi, ok := parsePortRange(p.Port, "-"); ok {
			specs = append(specs, portSpec{protocol: proto, from: lo, to: hi})
		}
	}
	return specs, true
}

// firewalldServiceName is what a firewalld service name can look like; any
// other name in the probe output is not looked up on disk.
var firewalldServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// interfaceNameFunc returns the name of the interface holding addr.
type interfaceNameFunc func(addr netip.Addr) (name string, ok bool)

// firewalldCheck rates a socket against the zones that can receive its
// traffic. firewalld puts a packet in the zone of its source address, else
// the zone of its incoming interface, else the default zone. So a socket
// bound to one interface's address is governed by the source zones and that
// interface's zone (or the default zone when the interface has none); a
// wildcard socket by every active zone, plus the default zone when an
// arrival interface (see newFirewalldZoneSet) has no zone. When the socket's
// interface can't be found, the verdict is unknown.
//
// A zone lets a port in when its target is ACCEPT, or it opens the port
// through a service, a port or a rich rule. serviceSpecs resolves a service
// name; ok is false when its definition can't be read, which makes an
// otherwise blocked verdict unknown. Lookups are cached per check.
func firewalldCheck(zones []firewalldZone, serviceSpecs func(name string) ([]portSpec, bool), ifaceName interfaceNameFunc, arrival []string) firewallCheck {
	set := newFirewalldZoneSet(zones, arrival)
	services := map[string]firewalldService{}
	lookup := func(name string) ([]portSpec, bool) {
		if s, ok := services[name]; ok {
			return s.specs, s.ok
		}
		var s firewalldService
		if firewalldServiceName.MatchString(name) {
			s.specs, s.ok = serviceSpecs(name)
		}
		services[name] = s
		return s.specs, s.ok
	}
	return func(p shared.ListeningPort) firewallResult {
		zones, ok := set.forSocket(p.Address, ifaceName)
		if !ok || len(zones) == 0 {
			return firewallResult{verdict: firewallUnknown}
		}
		uncertain, allowed := false, false
		var scope remoteScope
		var via ifaceSet
		for _, z := range zones {
			verdict, s := z.lets(p, lookup)
			switch verdict {
			case firewallAllowed:
				allowed = true
				scope.merge(s)
				for _, name := range set.arrivalsOf(z, arrival) {
					via.add(name)
				}
			case firewallUnknown:
				uncertain = true
			}
		}
		switch {
		case allowed && uncertain:
			// Another zone's unresolved service may let anyone in.
			scope.widen(remoteUnknown)
			via.add("")
			return firewallResult{verdict: firewallAllowed, scope: scope, via: via}
		case allowed:
			return firewallResult{verdict: firewallAllowed, scope: scope, via: via}
		case uncertain:
			return firewallResult{verdict: firewallUnknown}
		}
		return firewallResult{verdict: firewallBlocked}
	}
}

type firewalldService struct {
	specs []portSpec
	ok    bool
}

// firewalldZoneSet sorts the zones by how they receive traffic.
type firewalldZoneSet struct {
	active      []firewalldZone // in force: active zones, else the default zone
	sourceZones []firewalldZone
	byInterface map[string]firewalldZone
	defaultZone *firewalldZone
}

// newFirewalldZoneSet sorts zones. arrival lists the interfaces connections
// can come in on (nil when unknown): traffic on one no zone claims goes to
// the default zone, so a wildcard socket is governed by the default zone too
// unless every arrival interface is bound to a zone.
func newFirewalldZoneSet(zones []firewalldZone, arrival []string) firewalldZoneSet {
	set := firewalldZoneSet{byInterface: map[string]firewalldZone{}}
	for i, z := range zones {
		if z.isDefault {
			set.defaultZone = &zones[i]
		}
		if !z.active {
			continue
		}
		set.active = append(set.active, z)
		if len(z.sources) > 0 {
			set.sourceZones = append(set.sourceZones, z)
		}
		for _, iface := range z.interfaces {
			set.byInterface[iface] = z
		}
	}
	if set.defaultZone != nil && !set.defaultZone.active && (len(set.active) == 0 || set.unboundArrival(arrival)) {
		set.active = append(set.active, *set.defaultZone)
	}
	return set
}

// unboundArrival reports whether a connection can arrive on an interface no
// zone is bound to, assuming so when the interfaces are unknown.
func (s firewalldZoneSet) unboundArrival(arrival []string) bool {
	if arrival == nil {
		return true
	}
	for _, iface := range arrival {
		if _, ok := s.byInterface[iface]; !ok {
			return true
		}
	}
	return false
}

// arrivalsOf returns the interfaces connections come into zone z on, or
// [""] for every interface: a zone bound to sources takes their traffic on
// any interface, the default zone takes traffic on every interface no other
// zone claims (every one when the interfaces are unknown), and any other
// zone the traffic on its own interfaces.
func (s firewalldZoneSet) arrivalsOf(z firewalldZone, arrival []string) []string {
	if len(z.sources) > 0 || (len(z.interfaces) == 0 && !z.isDefault) {
		return []string{""}
	}
	names := slices.Clone(z.interfaces)
	if z.isDefault {
		if arrival == nil {
			return []string{""}
		}
		for _, iface := range arrival {
			if _, bound := s.byInterface[iface]; !bound {
				names = append(names, iface)
			}
		}
	}
	return names
}

// forSocket returns the zones governing a socket bound to addr. ok is false
// when the socket is bound to an interface that can't be identified.
func (s firewalldZoneSet) forSocket(addr string, ifaceName interfaceNameFunc) ([]firewalldZone, bool) {
	if bindScope(addr) != scopeInterface {
		return s.active, true
	}
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"))
	if err != nil || ifaceName == nil {
		return nil, false
	}
	name, ok := ifaceName(a.Unmap().WithZone(""))
	if !ok {
		return nil, false
	}
	zones := append([]firewalldZone{}, s.sourceZones...)
	if z, ok := s.byInterface[name]; ok {
		return append(zones, z), true
	}
	if s.defaultZone != nil {
		zones = append(zones, *s.defaultZone)
	}
	return zones, true
}

// lets returns whether the zone lets connections to p in (allowed, blocked,
// or unknown when a service it opens can't be resolved) and from where: a
// zone bound only to source addresses takes traffic only from them, and a
// rich rule with a source admits only that source; anything else admits any
// address. A zone bound to interfaces too takes all their traffic, whatever
// its source. When the zone allows p but one of its services can't be
// resolved, that service may let its sources in too: any source makes the
// scope unknown.
func (z firewalldZone) lets(p shared.ListeningPort, lookup func(string) ([]portSpec, bool)) (string, remoteScope) {
	var scope remoteScope
	sourceOnly := len(z.sources) > 0 && len(z.interfaces) == 0
	from := func(source string) {
		switch {
		case source != "":
			scope.widen(remoteSpecific, source)
		case sourceOnly:
			scope.widen(remoteSpecific, z.sources...)
		default:
			scope.widen(remoteAny)
		}
	}
	if strings.EqualFold(z.target, "ACCEPT") || anyCovers(z.ports, p) {
		from("")
	}
	for _, source := range z.sourceAll {
		from(source)
	}
	for _, r := range z.richOpen {
		if r.spec.covers(p) {
			from(r.source)
		}
	}
	unresolved := false
	var maybe remoteScope
	services := func(name, source string) {
		specs, ok := lookup(name)
		switch {
		case !ok:
			unresolved = true
			switch {
			case source != "":
				maybe.widen(remoteSpecific, source)
			case sourceOnly:
				maybe.widen(remoteSpecific, z.sources...)
			default:
				maybe.widen(remoteUnknown)
			}
		case anyCovers(specs, p):
			from(source)
		}
	}
	for _, name := range z.services {
		services(name, "")
	}
	for _, r := range z.richSvcs {
		services(r.name, r.source)
	}
	switch {
	case scope.kind != "":
		scope.merge(maybe)
		return firewallAllowed, scope
	case unresolved:
		return firewallUnknown, remoteScope{}
	}
	return firewallBlocked, remoteScope{}
}

// ── macOS Application Firewall ───────────────────────────────────────────────

// alfBlocksAll reports whether socketfilterfw's output says the firewall
// blocks all incoming connections: "--getblockall" prints "Firewall has
// block all state set to enabled." (older releases "Block all ENABLED!"),
// and "--getglobalstate" reports state 2.
func alfBlocksAll(blockAll, globalState string) bool {
	b := strings.ToLower(blockAll)
	if strings.Contains(b, "block all") && strings.Contains(b, "enabled") {
		return true
	}
	return strings.Contains(globalState, "State = 2")
}
