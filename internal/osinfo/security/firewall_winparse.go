package security

// Windows firewall reachability (#221). No OS suffix so it is tested
// everywhere; firewall_windows.go reads the data.

import (
	"encoding/json"
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

type winFwProfile struct {
	Name           string `json:"name"` // "Domain", "Private" or "Public"
	Enabled        bool   `json:"enabled"`
	DefaultInbound string `json:"default_inbound"` // "Block", "Allow" or "NotConfigured" (= Block)
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
// Every rule has a port and a program filter. If the probe returned a rule
// without either, the policy is incomplete and every verdict is unknown: a
// missing filter must not be read as "any port" or "any program".
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
		if !hasPort || !hasApp {
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
		case ix.allows(name, p, strings.EqualFold(prof.DefaultInbound, "Allow")):
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
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"))
	if err != nil {
		return ix.active
	}
	if idx, ok := ix.ifaceIndex(a.Unmap().WithZone("")); ok {
		if p, known := ix.byIndex[idx]; known {
			return []string{p}
		}
	}
	return ix.active
}

// allows reports whether inbound connections to p get through on profile.
// A matching block rule wins over any allow rule, as in Windows Firewall
// (allow rules that override block rules are rare and not modelled); with no
// matching rule the profile's default inbound action decides.
func (ix winFwIndex) allows(profile string, p shared.ListeningPort, defaultAllow bool) bool {
	bit := 0
	for _, wp := range winProfiles {
		if wp.name == profile {
			bit = wp.bit
		}
	}
	allowed := defaultAllow
	for _, r := range ix.rules {
		if mask := r.Profile & 7; mask != 0 && mask&bit == 0 {
			continue
		}
		if !winRuleMatchesPort(ix.ports[r.ID], p) || !winRuleMatchesProgram(ix.apps[r.ID], p.ProcessName) {
			continue
		}
		switch {
		case strings.EqualFold(r.Action, "Block"):
			return false
		case strings.EqualFold(r.Action, "Allow"):
			allowed = true
		}
	}
	return allowed
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
