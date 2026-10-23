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
	Rules    []winFwRule       `json:"rules"` // enabled inbound rules
	Ports    []winFwPortFilter `json:"ports"`
	Apps     []winFwAppFilter  `json:"apps"`
	Addrs    []winFwAddrFilter `json:"addrs"`
	Profiles []winFwProfile    `json:"profiles"`
	Networks []winFwNetwork    `json:"networks"`
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
	profiles   map[string]winFwProfile
	active     []string       // profiles of the connected networks
	byIndex    map[int]string // interface index → its network's profile
	ifaceIndex interfaceIndexFunc
}

// checker returns the firewallCheck for this state. A socket bound to one
// interface's address is checked against that network's profile only; a
// wildcard socket, or one whose interface has no network profile, against
// every active profile. ifaceIndex may be nil.
//
// Every rule has a port, a program and an address filter. If the probe
// returned a rule without one, the policy is incomplete and every verdict is
// unknown: a missing filter must not be read as "any".
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
		profiles:   make(map[string]winFwProfile, len(fw.Profiles)),
		active:     fw.activeProfiles(),
		byIndex:    map[int]string{},
		ifaceIndex: ifaceIndex,
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
		if p := winProfileName(n.Category); p != "" && n.Index > 0 {
			ix.byIndex[n.Index] = p
		}
	}
	for _, r := range fw.Rules {
		_, hasPort := ix.ports[r.ID]
		_, hasApp := ix.apps[r.ID]
		_, hasAddr := ix.addrs[r.ID]
		if !hasPort || !hasApp || !hasAddr {
			return winFwIndex{}, false
		}
	}
	return ix, true
}

// check rates one socket: disabled when a governing profile has the
// firewall off, allowed when one lets connections in, blocked otherwise.
func (ix winFwIndex) check(p shared.ListeningPort) (string, []string) {
	var reachable []string
	disabled := false
	for _, name := range ix.socketProfiles(p.Address) {
		prof, known := ix.profiles[name]
		switch {
		case !known:
			return firewallUnknown, nil
		case !prof.Enabled:
			disabled = true
			reachable = append(reachable, name)
		case ix.allows(prof, p):
			reachable = append(reachable, name)
		}
	}
	switch {
	case disabled:
		return firewallDisabled, reachable
	case len(reachable) > 0:
		return firewallAllowed, reachable
	default:
		return firewallBlocked, nil
	}
}

// socketProfiles returns the firewall profiles that govern connections to a
// socket bound to addr.
func (ix winFwIndex) socketProfiles(addr string) []string {
	if ix.ifaceIndex == nil || bindScope(addr) != scopeInterface {
		return ix.active
	}
	a := winBoundAddr(addr)
	if !a.IsValid() {
		return ix.active
	}
	if idx, ok := ix.ifaceIndex(a); ok {
		if p, known := ix.byIndex[idx]; known {
			return []string{p}
		}
	}
	return ix.active
}

// allows reports whether inbound connections to p get through on a profile.
// A block rule wins over any allow rule, as in Windows Firewall (allow rules
// that override block rules are rare and not modelled), but only when it
// covers every connection to the socket: from any remote address, to the
// socket's address, for its program. A narrower block leaves the other
// connections to the allow rules. With no matching rule the profile's
// default inbound action decides; allow rules don't count when the profile
// blocks all incoming connections.
func (ix winFwIndex) allows(prof winFwProfile, p shared.ListeningPort) bool {
	bit := 0
	for _, wp := range winProfiles {
		if wp.name == prof.Name {
			bit = wp.bit
		}
	}
	bound := winBoundAddr(p.Address)
	allowed := strings.EqualFold(prof.DefaultInbound, "Allow")
	for _, r := range ix.rules {
		if mask := r.Profile & 7; mask != 0 && mask&bit == 0 {
			continue
		}
		if !winRuleMatchesPort(ix.ports[r.ID], p) {
			continue
		}
		addr := ix.addrs[r.ID]
		switch {
		case strings.EqualFold(r.Action, "Block"):
			if winAddrIsAny(addr.RemoteAddress) && winLocalCoversAll(addr.LocalAddress, bound) && winProgramCoversAll(ix.apps[r.ID], p.ProcessName) {
				return false
			}
		case strings.EqualFold(r.Action, "Allow") && !prof.BlockAllInbound:
			if winRuleMatchesProgram(ix.apps[r.ID], p.ProcessName) && winLocalReaches(addr.LocalAddress, bound) {
				allowed = true
			}
		}
	}
	return allowed
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
