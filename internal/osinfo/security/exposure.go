package security

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Bind scopes of a listening socket (#221).
const (
	scopeLoopback  = "loopback"  // 127.0.0.0/8, ::1, localhost: only this device can connect
	scopeAll       = "all"       // 0.0.0.0, ::, *: every interface
	scopeInterface = "interface" // one interface's address, link-local included
	scopeUnknown   = "unknown"   // not an address we can parse; treated as reachable
)

// bindScope classifies a listening socket's local address. Only loopback is
// unreachable from the network; anything unparseable counts as reachable.
func bindScope(addr string) string {
	a := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(addr), "["), "]")
	switch strings.ToLower(a) {
	case "localhost":
		return scopeLoopback
	case "*":
		return scopeAll
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return scopeUnknown
	}
	ip = ip.Unmap() // ::ffff:127.0.0.1 is loopback
	switch {
	case ip.IsLoopback():
		return scopeLoopback
	case ip.IsUnspecified():
		return scopeAll
	default:
		return scopeInterface
	}
}

// riskyPorts is a range of ports a commonly attacked service listens on.
type riskyPorts struct {
	name     string
	protocol string // "tcp" or "udp"
	from, to uint16
}

// riskyServiceCatalogue lists the services that make a device's network
// exposure High when reachable. It matches the console's risky-service
// catalogue (sentinel-ops#296), so the agent and console agree.
var riskyServiceCatalogue = []riskyPorts{
	{"FTP", "tcp", 21, 21},
	{"SSH", "tcp", 22, 22},
	{"Telnet", "tcp", 23, 23},
	{"NetBIOS", "udp", 137, 138},
	{"SMB", "tcp", 139, 139},
	{"SNMP", "udp", 161, 161},
	{"SMB", "tcp", 445, 445},
	{"MSSQL", "tcp", 1433, 1433},
	{"Docker API", "tcp", 2375, 2376},
	{"MySQL", "tcp", 3306, 3306},
	{"RDP", "tcp", 3389, 3389},
	{"RDP", "udp", 3389, 3389},
	{"PostgreSQL", "tcp", 5432, 5432},
	{"VNC", "tcp", 5900, 5906},
	{"WinRM", "tcp", 5985, 5986},
	{"Redis", "tcp", 6379, 6379},
	{"Elasticsearch", "tcp", 9200, 9200},
	{"Kubelet", "tcp", 10250, 10250},
	{"MongoDB", "tcp", 27017, 27017},
}

// riskyServiceName returns the catalogue name of the service p listens as,
// whatever address it's bound to.
func riskyServiceName(p shared.ListeningPort) (string, bool) {
	proto := strings.ToLower(p.Protocol)
	for _, r := range riskyServiceCatalogue {
		if r.protocol == proto && p.Port >= r.from && p.Port <= r.to {
			return r.name, true
		}
	}
	return "", false
}

// Verdicts on whether the host firewall lets a risky service be reached.
const (
	firewallAllowed  = "allowed"  // an inbound rule or the default policy lets connections in
	firewallBlocked  = "blocked"  // the host firewall drops inbound connections to it
	firewallDisabled = "disabled" // no host firewall is filtering inbound connections
	firewallUnknown  = "unknown"  // the agent couldn't tell
)

// Remote scopes: whom the host firewall's allow rules let in (#251), from
// the widest. The order matches the console's: unknown may be any.
const (
	remoteAny         = "any"          // every remote address
	remoteUnknown     = "unknown"      // allowed, but from where couldn't be told
	remoteLocalSubnet = "local_subnet" // only the subnets the host is on
	remoteSpecific    = "specific"     // only listed addresses or ranges
)

// maxRemoteAddresses caps RiskyService.RemoteAddresses.
const maxRemoteAddresses = 10

// remoteScopeRank orders the remote scopes, widest highest; 0 for none.
func remoteScopeRank(kind string) int {
	switch kind {
	case remoteAny:
		return 4
	case remoteUnknown:
		return 3
	case remoteLocalSubnet:
		return 2
	case remoteSpecific:
		return 1
	}
	return 0
}

// remoteScope accumulates whom the allow rules that let a socket in admit:
// the widest kind, and the addresses of the narrower ones.
type remoteScope struct {
	kind  string   // "" until an allow rule is seen
	addrs []string // remote addresses or ranges of the rules that aren't "any"
}

// widen adds an allow rule's remote scope. A specific range that covers
// every address (0.0.0.0/0, ::/0) is any.
func (s *remoteScope) widen(kind string, addrs ...string) {
	if kind == remoteSpecific && slices.ContainsFunc(addrs, isAllAddresses) {
		kind = remoteAny
	}
	if remoteScopeRank(kind) > remoteScopeRank(s.kind) {
		s.kind = kind
	}
	for _, a := range addrs {
		if a != "" && !slices.Contains(s.addrs, a) {
			s.addrs = append(s.addrs, a)
		}
	}
}

// merge adds another scope.
func (s *remoteScope) merge(o remoteScope) { s.widen(o.kind, o.addrs...) }

// isAllAddresses reports whether a remote range is a /0 prefix.
func isAllAddresses(addr string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(addr))
	return err == nil && p.Bits() == 0
}

// ifaceSet is the interfaces connections are let in on: every interface, or
// only the named ones. Only the Windows check names any: Windows accepts a
// packet only on the interface that holds its destination address, while
// Linux and macOS accept it on any interface.
type ifaceSet struct {
	every bool
	names []string
}

// add records an interface connections are let in on; "" for every one.
func (s *ifaceSet) add(name string) {
	if name == "" {
		s.every = true
		return
	}
	s.names = appendUnique(s.names, name)
}

// includes reports whether connections arriving on iface are let in. A set
// with no interfaces (the check didn't tell) includes every one.
func (s ifaceSet) includes(iface string) bool {
	return s.every || len(s.names) == 0 || slices.Contains(s.names, iface)
}

// firewallResult is a firewall check's finding on one socket.
type firewallResult struct {
	verdict  string
	profiles []string    // Windows: the active profiles that let connections in
	scope    remoteScope // whom the allow rules let in, when allowed
	via      ifaceSet    // Windows: the networks' interfaces they let them in on
}

// firewallCheck returns whether the host firewall lets inbound connections
// reach p, from where, and on Windows through which active profiles.
type firewallCheck func(p shared.ListeningPort) firewallResult

// constantCheck gives every risky service the same verdict.
func constantCheck(verdict string) firewallCheck {
	return func(shared.ListeningPort) firewallResult { return firewallResult{verdict: verdict} }
}

// reportedScope returns the RemoteScope and RemoteAddresses sent for a
// result: none unless the firewall lets connections in, "any" when it's off,
// "unknown" when the check couldn't tell from where, and the addresses only
// for "specific".
func reportedScope(r firewallResult) (string, []string) {
	switch r.verdict {
	case firewallDisabled:
		return remoteAny, nil
	case firewallAllowed:
	default:
		return "", nil
	}
	switch r.scope.kind {
	case "":
		return remoteUnknown, nil
	case remoteSpecific:
		addrs := r.scope.addrs
		if len(addrs) > maxRemoteAddresses {
			addrs = addrs[:maxRemoteAddresses]
		}
		return remoteSpecific, slices.Clone(addrs)
	}
	return r.scope.kind, nil
}

// nonPublicPrefixes are global-unicast ranges that aren't reachable from the
// internet: carrier-grade NAT, special-use, benchmarking, documentation and
// reserved space (RFC 6598, 6890, 2544, 5737, 3849, 1112).
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // NOSONAR CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // NOSONAR IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // NOSONAR TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // NOSONAR benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // NOSONAR TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // NOSONAR TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // NOSONAR reserved
	netip.MustParsePrefix("2001:db8::/32"),   // NOSONAR documentation
}

// isPublicAddr reports whether a is a public unicast address: not loopback,
// link-local, private (RFC 1918, IPv6 ULA), CGNAT or other special-use space.
func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// hostAddr is one address of one of the host's interfaces.
type hostAddr struct {
	iface string
	addr  netip.Addr
}

// hostAddrs lists the host's interface addresses; swapped in tests.
var hostAddrs = systemInterfaceAddrs

// onPublicAddress reports whether a socket bound to addr can be reached on a
// public address through the interfaces via lets connections in on: it's
// bound to a public address, or it's a wildcard socket and one of those
// interfaces has one of a family it accepts (IPv4 for 0.0.0.0, IPv6 for a
// "::" socket that is v6Only, either otherwise).
func onPublicAddress(addr string, via ifaceSet, v6Only bool) bool {
	families, bound := listenerFamilies(addr, v6Only)
	switch bindScope(addr) {
	case scopeLoopback:
		return false
	case scopeInterface:
		if !bound.IsValid() || !isPublicAddr(bound) {
			return false
		}
		for _, h := range hostAddrs() {
			if h.addr.Unmap().WithZone("") == bound {
				return via.includes(h.iface)
			}
		}
		return true
	}
	for _, h := range hostAddrs() {
		a := h.addr.Unmap()
		family := 6
		if a.Is4() {
			family = 4
		}
		if slices.Contains(families, family) && isPublicAddr(a) && via.includes(h.iface) {
			return true
		}
	}
	return false
}

// v4WildcardPorts returns whether a socket's port and protocol also have an
// IPv4 wildcard socket. A socket on "::" is then IPv6-only: Linux refuses
// that pair unless the IPv6 one is IPV6_V6ONLY, and on Windows and macOS the
// two are separate sockets. net.ipv6.bindv6only isn't used: it's only the
// default, a socket can still clear IPV6_V6ONLY, and /proc/net doesn't show
// which it did. Assuming dual-stack can overstate exposure but never hide it.
func v4WildcardPorts(ports []shared.ListeningPort) func(p shared.ListeningPort) bool {
	v4Wildcard := map[string]bool{}
	for _, p := range ports {
		if a, err := netip.ParseAddr(p.Address); err == nil && a.Is4() && a.IsUnspecified() {
			v4Wildcard[fmt.Sprintf("%s/%d", strings.ToLower(p.Protocol), p.Port)] = true
		}
	}
	return func(p shared.ListeningPort) bool {
		return v4Wildcard[fmt.Sprintf("%s/%d", strings.ToLower(p.Protocol), p.Port)]
	}
}

// remoteAccessProcessKeywords are process-name substrings that indicate a
// remote-access tool (case-insensitive match against the process name).
var remoteAccessProcessKeywords = []string{
	"ssh", "rdp", "vnc", "anydesk", "teamviewer", "remote", "pcanywhere",
}

// isRemoteAccessPort reports whether p looks like a remote-access service,
// either by its process name or by listening on a well-known remote-access port.
func isRemoteAccessPort(p shared.ListeningPort) bool {
	procLower := strings.ToLower(p.ProcessName)
	for _, kw := range remoteAccessProcessKeywords {
		if strings.Contains(procLower, kw) {
			return true
		}
	}
	return p.Port == 22 || p.Port == 3389 || (p.Port >= 5900 && p.Port <= 5906)
}

// analyzeNetworkExposure summarizes the listening sockets. Sockets bound to
// loopback count only toward TotalListeningPorts and ActiveNetworkServices:
// nothing on the network can reach them. check may be nil, which gives every
// risky service the verdict "unknown".
func analyzeNetworkExposure(ports []shared.ListeningPort, check firewallCheck) shared.NetworkExposureAccessInfo {
	var info shared.NetworkExposureAccessInfo
	info.TotalListeningPorts = len(ports)

	activeServicesMap := make(map[string]bool)
	remoteAccessMap := make(map[string]bool)
	for _, p := range ports {
		if p.ProcessName != "" {
			activeServicesMap[p.ProcessName] = true
		}
		if bindScope(p.Address) == scopeLoopback {
			continue
		}
		info.PubliclyBoundPorts++
		if isRemoteAccessPort(p) {
			name := p.ProcessName
			if name == "" {
				name = fmt.Sprintf("Unknown service on port %d", p.Port)
			}
			remoteAccessMap[name] = true
		}
	}
	info.ActiveNetworkServices = sortedKeys(activeServicesMap)
	info.RemoteAccessServices = sortedKeys(remoteAccessMap)

	info.RiskyServices = findRiskyServices(ports, check)
	info.OpenAdministrativePorts = []uint16{}
	for _, s := range info.RiskyServices {
		info.OpenAdministrativePorts = append(info.OpenAdministrativePorts, s.Port)
	}
	slices.Sort(info.OpenAdministrativePorts)
	info.OpenAdministrativePorts = slices.Compact(info.OpenAdministrativePorts)
	return info
}

// findRiskyServices returns the risky services listening on a non-loopback
// address, one per socket, with their firewall verdicts, sorted by port,
// protocol and address.
func findRiskyServices(ports []shared.ListeningPort, check firewallCheck) []shared.RiskyService {
	if check == nil {
		check = constantCheck(firewallUnknown)
	}
	v6Only := v4WildcardPorts(ports)
	risky := []shared.RiskyService{}
	seen := make(map[string]bool)
	for _, p := range ports {
		scope := bindScope(p.Address)
		name, ok := riskyServiceName(p)
		key := fmt.Sprintf("%s/%d/%s", strings.ToLower(p.Protocol), p.Port, p.Address)
		if scope == scopeLoopback || !ok || seen[key] {
			continue
		}
		seen[key] = true
		res := check(p)
		remote, addrs := reportedScope(res)
		risky = append(risky, shared.RiskyService{
			Name:              name,
			Port:              p.Port,
			Protocol:          strings.ToLower(p.Protocol),
			Address:           p.Address,
			Scope:             scope,
			ProcessName:       p.ProcessName,
			Firewall:          res.verdict,
			ReachableProfiles: res.profiles,
			RemoteScope:       remote,
			RemoteAddresses:   addrs,
			OnPublicAddress:   onPublicAddress(p.Address, res.via, v6Only(p)),
		})
	}
	slices.SortFunc(risky, func(a, b shared.RiskyService) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.Address, b.Address))
	})
	return risky
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Exposure tiers of a risky service, from the most severe.
const (
	tierPublic  = iota // let in from any address, on a public address
	tierAny            // let in from any address
	tierUnknown        // maybe let in from any address: the check couldn't tell
	tierLimited        // let in only from the local subnet or listed addresses
	tierBlocked        // the host firewall blocks it
	tierCount
)

// exposureTier rates one risky service. The firewall being off counts as
// letting everyone in; an unknown verdict or scope as possibly doing so.
func exposureTier(s shared.RiskyService) int {
	if s.Firewall == firewallBlocked {
		return tierBlocked
	}
	scope := s.RemoteScope
	switch {
	case s.Firewall == firewallDisabled:
		scope = remoteAny
	case s.Firewall != firewallAllowed || scope == "":
		scope = remoteUnknown
	}
	switch {
	case scope == remoteLocalSubnet || scope == remoteSpecific:
		return tierLimited
	case scope == remoteAny && s.OnPublicAddress:
		return tierPublic
	case scope == remoteAny:
		return tierAny
	default:
		return tierUnknown
	}
}

// exposureEntry is one risky service in a recommendation: its most severe
// tier, and the Windows profiles its sockets in that tier are let in on.
type exposureEntry struct {
	label    string
	tier     int
	profiles []string
}

// String names the service, with the Windows profiles that let it in.
func (e exposureEntry) String() string {
	if len(e.profiles) == 0 {
		return e.label
	}
	return e.label + " on the " + strings.Join(e.profiles, "/") + " network"
}

// summarizeNetworkExposureLevel rates exposure by the risky services on the
// network and whom the host firewall lets in, not by how many sockets are
// bound: Critical when one is let in from any address on a public address,
// High when one is let in from any address or the agent couldn't tell from
// where, Medium when they are let in only from the local subnet or listed
// addresses, or all blocked, Low when there are none. A service is listed
// once, under its most severe tier; blocked services only when nothing is
// let in.
func summarizeNetworkExposureLevel(net shared.NetworkExposureAccessInfo) (level string, recommendations []string) {
	var entries []*exposureEntry
	byLabel := map[string]*exposureEntry{}
	for _, s := range net.RiskyServices {
		label := fmt.Sprintf("%s (%d/%s)", s.Name, s.Port, s.Protocol)
		tier := exposureTier(s)
		e, seen := byLabel[label]
		switch {
		case !seen:
			e = &exposureEntry{label: label, tier: tier}
			byLabel[label] = e
			entries = append(entries, e)
		case tier < e.tier:
			e.tier, e.profiles = tier, nil
		case tier > e.tier:
			continue
		}
		for _, p := range s.ReachableProfiles {
			e.profiles = appendUnique(e.profiles, p)
		}
	}
	var lists [tierCount][]string
	for _, e := range entries {
		lists[e.tier] = append(lists[e.tier], e.String())
	}

	if l := lists[tierPublic]; len(l) > 0 {
		recommendations = append(recommendations, "Close or firewall "+strings.Join(l, ", ")+": allowed in from any address, on a public IP address.")
	}
	if l := lists[tierAny]; len(l) > 0 {
		recommendations = append(recommendations, "Close or firewall "+strings.Join(l, ", ")+": allowed in from any address.")
	}
	if l := lists[tierUnknown]; len(l) > 0 {
		recommendations = append(recommendations, "Close or firewall "+strings.Join(l, ", ")+": listening on the network, and the agent couldn't verify whom the host firewall lets in.")
	}
	if l := lists[tierLimited]; len(l) > 0 {
		recommendations = append(recommendations, "Check that "+strings.Join(l, ", ")+" should be reachable: allowed in only from the local subnet or listed addresses.")
	}
	if l := lists[tierBlocked]; len(l) > 0 && len(recommendations) == 0 {
		recommendations = append(recommendations, "Turn off "+strings.Join(l, ", ")+" if unused: listening on the network, though the host firewall blocks inbound connections.")
	}
	switch {
	case len(lists[tierPublic]) > 0:
		return "Critical", recommendations
	case len(lists[tierAny])+len(lists[tierUnknown]) > 0:
		return "High", recommendations
	case len(lists[tierLimited])+len(lists[tierBlocked]) > 0:
		return "Medium", recommendations
	default:
		return "Low", nil
	}
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}
