package security

// ufw, firewalld and macOS Application Firewall parsers (#221). No OS
// suffix so they are tested everywhere; firewall_linux.go and
// firewall_darwin.go call them.

import (
	"encoding/xml"
	"net/netip"
	"regexp"
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
}

type ufwStatus struct {
	active          bool
	defaultIncoming string // "deny", "reject" or "allow"
	rules           []ufwRule
}

var (
	ufwColumns   = regexp.MustCompile(`\s{2,}`)
	ufwInterface = regexp.MustCompile(` on \S+$`)
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

func ufwStrip(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "(v6)", ""))
	return strings.TrimSpace(ufwInterface.ReplaceAllString(s, ""))
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
	r := ufwRule{action: actionWords[0], anySource: ufwStrip(cols[2]) == "Anywhere"}

	to := ufwStrip(cols[0])
	// The destination may start with an address: "10.0.0.5 22/tcp".
	if first, rest, found := strings.Cut(to, " "); found && isAddressOrAnywhere(first) {
		to = strings.TrimSpace(rest)
	} else if isAddressOrAnywhere(to) {
		r.allPorts = true
		return r, true
	}
	if specs, ok := parsePortList(to, ":"); ok {
		r.ports = specs
	} else {
		r.app = to
	}
	return r, true
}

func isAddressOrAnywhere(s string) bool {
	if s == "Anywhere" {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
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
			if !ok || section == "" || strings.TrimSpace(key) != "ports" {
				continue
			}
			for _, group := range strings.Split(val, "|") {
				if specs, ok := parsePortList(group, ":"); ok {
					apps[section] = append(apps[section], specs...)
				}
			}
		}
	}
	return apps
}

// check evaluates the rules in order, as ufw does: the first rule matching
// the port decides, except that a deny from specific sources only blocks
// those sources. Rules naming an application profile that isn't installed
// make an otherwise blocked verdict unknown.
func (st ufwStatus) check(apps map[string][]portSpec) firewallCheck {
	return func(p shared.ListeningPort) (string, []string) {
		uncertain := false
		for _, r := range st.rules {
			switch {
			case r.allPorts:
			case r.app != "":
				specs, known := apps[r.app]
				if !known {
					uncertain = true
					continue
				}
				if !anyCovers(specs, p) {
					continue
				}
			case !anyCovers(r.ports, p):
				continue
			}
			switch r.action {
			case "allow", "limit":
				return firewallAllowed, nil
			case "deny", "reject":
				if r.anySource {
					return firewallBlocked, nil
				}
			}
		}
		if st.defaultIncoming == "allow" {
			return firewallAllowed, nil
		}
		if uncertain {
			return firewallUnknown, nil
		}
		return firewallBlocked, nil
	}
}

// ── firewalld ────────────────────────────────────────────────────────────────

type firewalldZone struct {
	name      string
	active    bool
	isDefault bool
	target    string
	services  []string
	ports     []portSpec
	richOpen  []portSpec // ports a rich rule accepts
	richSvcs  []string   // services a rich rule accepts
	sourceAll bool       // a rich rule accepts everything from some source
}

var (
	richPort    = regexp.MustCompile(`port port="([^"]+)" protocol="(tcp|udp)"`)
	richService = regexp.MustCompile(`service name="([^"]+)"`)
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
		if ok && !strings.HasPrefix(strings.TrimSpace(line), "rule ") {
			inRich = key == "rich rules"
			switch key {
			case "target":
				cur.target = strings.TrimSpace(val)
			case "services":
				cur.services = strings.Fields(val)
			case "ports":
				for _, f := range strings.Fields(val) {
					if specs, ok := parsePortList(f, "-"); ok {
						cur.ports = append(cur.ports, specs...)
					}
				}
			}
			continue
		}
		if inRich {
			cur.addRichRule(strings.TrimSpace(line))
		}
	}
	return zones
}

// addRichRule records what an accepting rich rule opens.
func (z *firewalldZone) addRichRule(rule string) {
	if !strings.HasSuffix(rule, " accept") && !strings.Contains(rule, " accept ") {
		return
	}
	switch {
	case richPort.MatchString(rule):
		m := richPort.FindStringSubmatch(rule)
		if lo, hi, ok := parsePortRange(m[1], "-"); ok {
			z.richOpen = append(z.richOpen, portSpec{protocol: m[2], from: lo, to: hi})
		}
	case richService.MatchString(rule):
		z.richSvcs = append(z.richSvcs, richService.FindStringSubmatch(rule)[1])
	case !strings.Contains(rule, " port ") && !strings.Contains(rule, " protocol ") && !strings.Contains(rule, "icmp"):
		z.sourceAll = true
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

// firewalldCheck: a port is reachable when an active zone (or the default
// zone, when none is active) accepts everything, or opens it through a
// service, a port or a rich rule. serviceSpecs resolves a service name;
// ok is false when its definition can't be read, which makes an otherwise
// blocked verdict unknown.
func firewalldCheck(zones []firewalldZone, serviceSpecs func(name string) ([]portSpec, bool)) firewallCheck {
	var inForce []firewalldZone
	for _, z := range zones {
		if z.active {
			inForce = append(inForce, z)
		}
	}
	if len(inForce) == 0 {
		for _, z := range zones {
			if z.isDefault {
				inForce = append(inForce, z)
			}
		}
	}
	return func(p shared.ListeningPort) (string, []string) {
		if len(inForce) == 0 {
			return firewallUnknown, nil
		}
		uncertain := false
		for _, z := range inForce {
			if strings.EqualFold(z.target, "ACCEPT") || z.sourceAll || anyCovers(z.ports, p) || anyCovers(z.richOpen, p) {
				return firewallAllowed, nil
			}
			for _, name := range append(append([]string{}, z.services...), z.richSvcs...) {
				specs, ok := serviceSpecs(name)
				if !ok {
					uncertain = true
					continue
				}
				if anyCovers(specs, p) {
					return firewallAllowed, nil
				}
			}
		}
		if uncertain {
			return firewallUnknown, nil
		}
		return firewallBlocked, nil
	}
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
