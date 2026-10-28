package security

// Windows firewall reachability (#221). No OS suffix so it is tested
// everywhere; firewall_windows.go reads the data.

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// winFirewall is the inbound firewall state read from the ActiveStore, the
// policy in force: local rules merged with Group Policy.
type winFirewall struct {
	Rules      []winFwRule            `json:"rules"` // enabled inbound rules
	Ports      []winFwPortFilter      `json:"ports"`
	Apps       []winFwAppFilter       `json:"apps"`
	Addrs      []winFwAddrFilter      `json:"addrs"`
	Services   []winFwServiceFilter   `json:"services"`
	Ifaces     []winFwIfaceFilter     `json:"ifaces"`
	IfaceTypes []winFwIfaceTypeFilter `json:"iface_types"`
	Profiles   []winFwProfile         `json:"profiles"`
	Networks   []winFwNetwork         `json:"networks"`
	// Hosted lists the running Windows services and the process hosting
	// each, to match rules limited to a service. Empty when it can't be read.
	Hosted []winHostedService `json:"hosted"`
}

type winFwRule struct {
	ID      string `json:"id"`
	Action  string `json:"action"`  // "Allow" or "Block"
	Profile int    `json:"profile"` // flags: Domain 1, Private 2, Public 4; 0 = any
}

type winFwPortFilter struct {
	ID        string `json:"id"`
	Protocol  string `json:"protocol"`   // "TCP", "UDP", "Any" or a protocol number
	LocalPort string `json:"local_port"` // comma-separated: "Any", "445", "5900-5906", "RPC", …
}

type winFwAppFilter struct {
	ID      string `json:"id"`
	Program string `json:"program"` // "Any", "System" or a path
}

// winFwAddrFilter holds comma-separated address lists: "Any", addresses,
// subnets ("10.0.0.0/24", "10.0.0.0/255.255.255.0"), ranges
// ("10.0.0.1-10.0.0.9") or keywords ("LocalSubnet", "Internet", …).
type winFwAddrFilter struct {
	ID            string `json:"id"`
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
}

// winFwServiceFilter limits a rule to one Windows service ("Any" for none).
type winFwServiceFilter struct {
	ID      string `json:"id"`
	Service string `json:"service"`
}

// winFwIfaceFilter limits a rule to interfaces by alias: comma-separated,
// or "Any".
type winFwIfaceFilter struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
}

// winFwIfaceTypeFilter limits a rule to interface types: "Any", or
// comma-separated "Wired", "Wireless", "RemoteAccess".
type winFwIfaceTypeFilter struct {
	ID            string `json:"id"`
	InterfaceType string `json:"interface_type"`
}

// winHostedService is a running service and the PID of its host process.
type winHostedService struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
}

type winFwProfile struct {
	Name           string `json:"name"` // "Domain", "Private" or "Public"
	Enabled        bool   `json:"enabled"`
	DefaultInbound string `json:"default_inbound"` // "Block", "Allow" or "NotConfigured" (= Block)
	// BlockAllInbound is "block all incoming connections, including those
	// in the list of allowed apps" (AllowInboundRules False): allow rules
	// are ignored.
	BlockAllInbound bool `json:"block_all_inbound"`
}

type winFwNetwork struct {
	Interface string `json:"interface"`
	Index     int    `json:"index"`    // InterfaceIndex, as net.Interface.Index
	Category  string `json:"category"` // "Public", "Private" or "DomainAuthenticated"
	Media     string `json:"media"`    // the adapter's PhysicalMediaType, e.g. "802.3", "Native 802.11"
}

// interfaceType maps the network's adapter media to a rule's interface
// type, or "" when it can't be told.
func (n winFwNetwork) interfaceType() string {
	m := strings.ToLower(n.Media)
	switch {
	case strings.Contains(m, "802.11") || strings.Contains(m, "wireless"):
		return "Wireless"
	case strings.Contains(m, "802.3"):
		return "Wired"
	}
	return ""
}

// winProfiles are the firewall profiles in flag order.
var winProfiles = []struct {
	name string
	bit  int
}{{"Domain", 1}, {"Private", 2}, {"Public", 4}}

// parseWinFirewall decodes the probe's JSON. ok is false when it can't be
// used: no output, bad JSON, or no profile states.
func parseWinFirewall(out string) (fw winFirewall, ok bool) {
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &fw) != nil || len(fw.Profiles) == 0 {
		return winFirewall{}, false
	}
	return fw, true
}

// winProfileName maps a network category to the firewall profile it uses.
func winProfileName(category string) string {
	if strings.EqualFold(category, "DomainAuthenticated") {
		return "Domain"
	}
	for _, p := range winProfiles {
		if strings.EqualFold(category, p.name) {
			return p.name
		}
	}
	return ""
}

// networkProfiles lists the firewall profile in force on each connected
// network.
func (fw winFirewall) networkProfiles() []shared.NetworkFirewallProfile {
	var out []shared.NetworkFirewallProfile
	for _, n := range fw.Networks {
		if p := winProfileName(n.Category); p != "" {
			out = append(out, shared.NetworkFirewallProfile{Interface: n.Interface, Profile: p})
		}
	}
	return out
}

// activeProfiles returns the profiles of the connected networks. With none
// connected every profile is checked, so a device that's offline right now is
// rated on what it would expose on any network.
func (fw winFirewall) activeProfiles() []string {
	active := map[string]bool{}
	for _, n := range fw.Networks {
		if p := winProfileName(n.Category); p != "" {
			active[p] = true
		}
	}
	var out []string
	for _, p := range winProfiles {
		if len(active) == 0 || active[p.name] {
			out = append(out, p.name)
		}
	}
	return out
}

// interfaceIndexFunc returns the index of the network interface that holds
// addr; ok is false when no interface does.
type interfaceIndexFunc func(addr netip.Addr) (index int, ok bool)

// winFwIndex is a winFirewall indexed for checking sockets.
type winFwIndex struct {
	rules      []winFwRule
	ports      map[string]winFwPortFilter
	apps       map[string]string
	addrs      map[string]winFwAddrFilter
	services   map[string]string
	ifaces     map[string]string
	ifaceTypes map[string]string
	hosted     map[int][]string // PID → the services it hosts
	profiles   map[string]winFwProfile
	active     []string             // profiles of the connected networks
	networks   []winFwNetwork       // connected networks with a known profile
	byIndex    map[int]winFwNetwork // interface index → its network
	ifaceIndex interfaceIndexFunc
}

// checker returns the firewallCheck for this state. A socket bound to one
// interface's address is checked against that network's profile only; a
// wildcard socket, or one whose interface has no network profile, against
// every active profile. ifaceIndex may be nil.
//
// Every rule has a port, program, address, service, interface and
// interface-type filter. If the probe returned a rule without one, the
// policy is incomplete and every verdict is unknown: a missing filter must
// not be read as "any".
func (fw winFirewall) checker(ifaceIndex interfaceIndexFunc) firewallCheck {
	ix, complete := fw.index(ifaceIndex)
	if !complete {
		return constantCheck(firewallUnknown)
	}
	return ix.check
}

func (fw winFirewall) index(ifaceIndex interfaceIndexFunc) (winFwIndex, bool) {
	ix := winFwIndex{
		rules:      fw.Rules,
		ports:      make(map[string]winFwPortFilter, len(fw.Ports)),
		apps:       make(map[string]string, len(fw.Apps)),
		addrs:      make(map[string]winFwAddrFilter, len(fw.Addrs)),
		services:   make(map[string]string, len(fw.Services)),
		ifaces:     make(map[string]string, len(fw.Ifaces)),
		ifaceTypes: make(map[string]string, len(fw.IfaceTypes)),
		hosted:     map[int][]string{},
		profiles:   make(map[string]winFwProfile, len(fw.Profiles)),
		active:     fw.activeProfiles(),
		byIndex:    map[int]winFwNetwork{},
		ifaceIndex: ifaceIndex,
	}
	for _, f := range fw.Services {
		ix.services[f.ID] = f.Service
	}
	for _, f := range fw.Ifaces {
		ix.ifaces[f.ID] = f.Interface
	}
	for _, f := range fw.IfaceTypes {
		ix.ifaceTypes[f.ID] = f.InterfaceType
	}
	for _, h := range fw.Hosted {
		if h.PID > 0 {
			ix.hosted[h.PID] = append(ix.hosted[h.PID], h.Name)
		}
	}
	for _, f := range fw.Ports {
		ix.ports[f.ID] = f
	}
	for _, f := range fw.Apps {
		ix.apps[f.ID] = f.Program
	}
	for _, f := range fw.Addrs {
		ix.addrs[f.ID] = f
	}
	for _, p := range fw.Profiles {
		ix.profiles[p.Name] = p
	}
	for _, n := range fw.Networks {
		if winProfileName(n.Category) == "" {
			continue
		}
		ix.networks = append(ix.networks, n)
		if n.Index > 0 {
			ix.byIndex[n.Index] = n
		}
	}
	for _, r := range fw.Rules {
		_, hasPort := ix.ports[r.ID]
		_, hasApp := ix.apps[r.ID]
		_, hasAddr := ix.addrs[r.ID]
		_, hasSvc := ix.services[r.ID]
		_, hasIface := ix.ifaces[r.ID]
		_, hasType := ix.ifaceTypes[r.ID]
		if !hasPort || !hasApp || !hasAddr || !hasSvc || !hasIface || !hasType {
			return winFwIndex{}, false
		}
	}
	return ix, true
}

// winArrival is a way connections reach a socket: through a firewall
// profile, on a connected network when known.
type winArrival struct {
	profile string
	network *winFwNetwork // nil when the network can't be told
}

// check rates one socket: disabled when a governing profile has the
// firewall off, allowed when one lets connections in, blocked otherwise.
// The scope is whom the allow rules (or a default inbound Allow) let in.
func (ix winFwIndex) check(p shared.ListeningPort) firewallResult {
	var reachable []string
	var scope remoteScope
	disabled := false
	for _, a := range ix.socketArrivals(p.Address) {
		prof, known := ix.profiles[a.profile]
		switch {
		case !known:
			return firewallResult{verdict: firewallUnknown}
		case !prof.Enabled:
			disabled = true
			reachable = appendUnique(reachable, a.profile)
		default:
			if ok, s := ix.allows(prof, a.network, p); ok {
				reachable = appendUnique(reachable, a.profile)
				scope.merge(s)
			}
		}
	}
	switch {
	case disabled:
		return firewallResult{verdict: firewallDisabled, profiles: reachable}
	case len(reachable) > 0:
		return firewallResult{verdict: firewallAllowed, profiles: reachable, scope: scope}
	default:
		return firewallResult{verdict: firewallBlocked}
	}
}

// socketArrivals returns how connections reach a socket bound to addr. A
// socket on one interface's address is reached through that interface's
// network. A wildcard socket is reached through every connected network,
// each judged on its own, since rules can be limited to an interface. With
// no network known, every active profile governs it.
func (ix winFwIndex) socketArrivals(addr string) []winArrival {
	if ix.ifaceIndex != nil && bindScope(addr) == scopeInterface {
		if a := winBoundAddr(addr); a.IsValid() {
			if idx, ok := ix.ifaceIndex(a); ok {
				if n, known := ix.byIndex[idx]; known {
					return []winArrival{{profile: winProfileName(n.Category), network: &n}}
				}
			}
		}
	} else if bindScope(addr) != scopeInterface && len(ix.networks) > 0 {
		out := make([]winArrival, 0, len(ix.networks))
		for i := range ix.networks {
			out = append(out, winArrival{profile: winProfileName(ix.networks[i].Category), network: &ix.networks[i]})
		}
		return out
	}
	out := make([]winArrival, 0, len(ix.active))
	for _, name := range ix.active {
		out = append(out, winArrival{profile: name})
	}
	return out
}

// allows reports whether inbound connections to p get through on a profile,
// arriving on network (nil when unknown), and whom they're let in from. A
// block rule wins over any allow rule, as in Windows Firewall (allow rules
// that override block rules are rare and not modelled), but only when it
// covers every connection to the socket: from any remote address, to the
// socket's address, for its program and service, on this interface. A
// narrower block leaves the other connections to the allow rules. With no
// matching rule the profile's default inbound action decides; allow rules
// don't count when the profile blocks all incoming connections.
func (ix winFwIndex) allows(prof winFwProfile, network *winFwNetwork, p shared.ListeningPort) (bool, remoteScope) {
	bit := 0
	for _, wp := range winProfiles {
		if wp.name == prof.Name {
			bit = wp.bit
		}
	}
	bound := winBoundAddr(p.Address)
	var scope remoteScope
	allowed := strings.EqualFold(prof.DefaultInbound, "Allow")
	if allowed {
		scope.widen(remoteAny)
	}
	for _, r := range ix.rules {
		if mask := r.Profile & 7; mask != 0 && mask&bit == 0 {
			continue
		}
		if !winRuleMatchesPort(ix.ports[r.ID], p) {
			continue
		}
		onIface, ifaceCertain := winRuleOnInterface(ix.ifaces[r.ID], ix.ifaceTypes[r.ID], network)
		if !onIface {
			continue
		}
		addr := ix.addrs[r.ID]
		forService, serviceCertain := ix.ruleForService(ix.services[r.ID], p)
		switch {
		case strings.EqualFold(r.Action, "Block"):
			if ifaceCertain && forService && serviceCertain && winAddrIsAny(addr.RemoteAddress) &&
				winLocalCoversAll(addr.LocalAddress, bound) && winProgramCoversAll(ix.apps[r.ID], p.ProcessName) {
				return false, remoteScope{}
			}
		case strings.EqualFold(r.Action, "Allow") && !prof.BlockAllInbound:
			if forService && winRuleMatchesProgram(ix.apps[r.ID], p.ProcessName) && winLocalReaches(addr.LocalAddress, bound) {
				allowed = true
				scope.merge(winRemoteScope(addr.RemoteAddress))
			}
		}
	}
	return allowed, scope
}

// winRuleOnInterface reports whether a rule's interface and interface-type
// filters let it apply on network. When the network or its type can't be
// told, a limited rule is assumed to apply (an over-report) but not for
// certain, so it can't count as a block covering every connection.
func winRuleOnInterface(aliases, types string, network *winFwNetwork) (applies, certain bool) {
	certain = true
	if !winAddrIsAny(aliases) {
		if network == nil {
			certain = false
		} else if !winListHas(aliases, network.Interface) {
			return false, true
		}
	}
	if !winAddrIsAny(types) {
		t := ""
		if network != nil {
			t = network.interfaceType()
		}
		if t == "" {
			certain = false
		} else if !winListHas(types, t) {
			return false, true
		}
	}
	return true, certain
}

// winListHas reports whether a comma-separated list holds item, ignoring case.
func winListHas(list, item string) bool {
	for _, x := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(x), item) {
			return true
		}
	}
	return false
}

// ruleForService reports whether a rule's service filter covers the
// listening process: "Any", or a service the process hosts. When the
// process's services can't be told (no PID, or the service list couldn't be
// read) the rule is assumed to match, an over-report, but not for certain.
func (ix winFwIndex) ruleForService(service string, p shared.ListeningPort) (match, certain bool) {
	if winAddrIsAny(service) {
		return true, true
	}
	if p.ProcessID <= 0 || len(ix.hosted) == 0 {
		return true, false
	}
	for _, name := range ix.hosted[int(p.ProcessID)] {
		if strings.EqualFold(name, strings.TrimSpace(service)) {
			return true, true
		}
	}
	return false, true
}

// winRemoteScope maps an allow rule's remote address filter to whom it lets
// in, the widest of its items: "Any", "Internet" and "DefaultGateway" let in
// any address, "LocalSubnet" the local subnets, and everything else
// (addresses, ranges, "Intranet", "DNS", "DHCP", "WINS", …) only those.
func winRemoteScope(spec string) remoteScope {
	var s remoteScope
	if winAddrIsAny(spec) {
		s.widen(remoteAny)
		return s
	}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		switch strings.ToLower(item) {
		case "", "any", "internet", "defaultgateway":
			s.widen(remoteAny)
		case "localsubnet", "localsubnet4", "localsubnet6":
			s.widen(remoteLocalSubnet)
		default:
			s.widen(remoteSpecific, item)
		}
	}
	return s
}

// winBoundAddr returns the address a socket is bound to, or the zero Addr
// for a wildcard socket or one whose address can't be parsed.
func winBoundAddr(addr string) netip.Addr {
	if bindScope(addr) != scopeInterface {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// winAddrIsAny reports whether an address filter is "Any".
func winAddrIsAny(spec string) bool {
	spec = strings.TrimSpace(spec)
	return spec == "" || strings.EqualFold(spec, "Any")
}

// winLocalReaches reports whether an allow rule's local addresses can let
// connections reach the socket: a wildcard socket takes connections to any
// of the host's addresses, and a filter that can't be evaluated is assumed
// to reach it.
func winLocalReaches(spec string, bound netip.Addr) bool {
	if winAddrIsAny(spec) || !bound.IsValid() {
		return true
	}
	match, known := winAddrMatches(spec, bound)
	return match || !known
}

// winLocalCoversAll reports whether a block rule's local addresses cover
// every connection to the socket. A wildcard socket also takes connections
// to addresses the rule doesn't name.
func winLocalCoversAll(spec string, bound netip.Addr) bool {
	if winAddrIsAny(spec) {
		return true
	}
	if !bound.IsValid() {
		return false
	}
	match, _ := winAddrMatches(spec, bound)
	return match
}

// winProgramCoversAll reports whether a block rule's program filter covers
// the listening process for certain: "Any", or the process itself. A rule
// for one program doesn't decide when the process is unknown.
func winProgramCoversAll(program, process string) bool {
	program = strings.TrimSpace(program)
	if program == "" || strings.EqualFold(program, "Any") {
		return true
	}
	return process != "" && winRuleMatchesProgram(program, process)
}

// winAddrMatches reports whether a comma-separated address filter includes
// a. known is false when it doesn't and an item (a keyword such as
// "LocalSubnet") couldn't be evaluated.
func winAddrMatches(spec string, a netip.Addr) (match, known bool) {
	known = true
	for _, item := range strings.Split(spec, ",") {
		m, ok := winAddrItemMatches(strings.TrimSpace(item), a)
		switch {
		case !ok:
			known = false
		case m:
			return true, true
		}
	}
	return false, known
}

// winAddrItemMatches matches one item of an address filter: "Any", an
// address, a subnet in CIDR or mask form, or a range. ok is false for
// anything else.
func winAddrItemMatches(item string, a netip.Addr) (match, ok bool) {
	if strings.EqualFold(item, "Any") {
		return true, true
	}
	if x, err := netip.ParseAddr(item); err == nil {
		return x.Unmap() == a, true
	}
	if lo, hi, isRange := strings.Cut(item, "-"); isRange {
		l, err1 := netip.ParseAddr(strings.TrimSpace(lo))
		h, err2 := netip.ParseAddr(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return false, false
		}
		l, h = l.Unmap(), h.Unmap()
		return l.BitLen() == a.BitLen() && l.Compare(a) <= 0 && a.Compare(h) <= 0, true
	}
	if p, err := netip.ParsePrefix(item); err == nil {
		return p.Masked().Contains(a), true
	}
	if ip, mask, isMask := strings.Cut(item, "/"); isMask {
		x, err1 := netip.ParseAddr(ip)
		m, err2 := netip.ParseAddr(mask)
		if err1 != nil || err2 != nil || !x.Is4() || !m.Is4() {
			return false, false
		}
		ones, bits := net.IPMask(m.AsSlice()).Size()
		if bits == 0 {
			return false, false
		}
		return netip.PrefixFrom(x, ones).Masked().Contains(a), true
	}
	return false, false
}

// winRuleMatchesPort reports whether a rule's protocol and local port cover
// p. A rule without a port filter covers every port.
func winRuleMatchesPort(f winFwPortFilter, p shared.ListeningPort) bool {
	switch strings.ToUpper(strings.TrimSpace(f.Protocol)) {
	case "", "ANY":
	case "TCP", "6":
		if !strings.EqualFold(p.Protocol, "tcp") {
			return false
		}
	case "UDP", "17":
		if !strings.EqualFold(p.Protocol, "udp") {
			return false
		}
	default: // ICMP and other protocols have no ports
		return false
	}
	spec := strings.TrimSpace(f.LocalPort)
	if spec == "" || strings.EqualFold(spec, "Any") {
		return true
	}
	for _, item := range strings.Split(spec, ",") {
		if lo, hi, ok := parsePortRange(strings.TrimSpace(item), "-"); ok && p.Port >= lo && p.Port <= hi {
			return true
		}
		// Keywords (RPC, RPCEPMap, IPHTTPSIn, Ply2Disc, mDNS, …) name
		// dynamic or service ports none of the risky services use.
	}
	return false
}

// winRuleMatchesProgram reports whether a rule's program filter covers the
// listening process. Rules are matched on the executable name, since the
// listener's path isn't collected; an unknown process matches every rule.
func winRuleMatchesProgram(program, process string) bool {
	program = strings.TrimSpace(program)
	if program == "" || strings.EqualFold(program, "Any") || process == "" {
		return true
	}
	if i := strings.LastIndexAny(program, `\/`); i >= 0 {
		program = program[i+1:]
	}
	return strings.EqualFold(program, process)
}

// parsePortRange parses "445" or "5900<sep>5906".
func parsePortRange(s, sep string) (lo, hi uint16, ok bool) {
	from, to, isRange := strings.Cut(s, sep)
	a, err := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
	if err != nil {
		return 0, 0, false
	}
	if !isRange {
		return uint16(a), uint16(a), true
	}
	b, err := strconv.ParseUint(strings.TrimSpace(to), 10, 16)
	if err != nil || b < a {
		return 0, 0, false
	}
	return uint16(a), uint16(b), true
}
