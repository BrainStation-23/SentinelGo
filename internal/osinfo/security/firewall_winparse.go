package security

// Windows firewall reachability (#221). No OS suffix so it is tested
// everywhere; firewall_windows.go reads the data.

import (
	"encoding/json"
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

// checker returns the firewallCheck for this state.
func (fw winFirewall) checker() firewallCheck {
	ports := make(map[string]winFwPortFilter, len(fw.Ports))
	for _, f := range fw.Ports {
		ports[f.ID] = f
	}
	apps := make(map[string]string, len(fw.Apps))
	for _, f := range fw.Apps {
		apps[f.ID] = f.Program
	}
	profiles := make(map[string]winFwProfile, len(fw.Profiles))
	for _, p := range fw.Profiles {
		profiles[p.Name] = p
	}
	active := fw.activeProfiles()

	return func(p shared.ListeningPort) (string, []string) {
		var reachable []string
		disabled := false
		for _, name := range active {
			prof, known := profiles[name]
			if !known {
				return firewallUnknown, nil
			}
			if !prof.Enabled {
				disabled = true
				reachable = append(reachable, name)
				continue
			}
			if fw.allows(name, p, ports, apps, strings.EqualFold(prof.DefaultInbound, "Allow")) {
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
}

// allows reports whether inbound connections to p get through on profile.
// A matching block rule wins over any allow rule, as in Windows Firewall
// (allow rules that override block rules are rare and not modelled); with no
// matching rule the profile's default inbound action decides.
func (fw winFirewall) allows(profile string, p shared.ListeningPort, ports map[string]winFwPortFilter, apps map[string]string, defaultAllow bool) bool {
	bit := 0
	for _, wp := range winProfiles {
		if wp.name == profile {
			bit = wp.bit
		}
	}
	allowed := defaultAllow
	for _, r := range fw.Rules {
		if mask := r.Profile & 7; mask != 0 && mask&bit == 0 {
			continue
		}
		if !winRuleMatchesPort(ports[r.ID], p) || !winRuleMatchesProgram(apps[r.ID], p.ProcessName) {
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
