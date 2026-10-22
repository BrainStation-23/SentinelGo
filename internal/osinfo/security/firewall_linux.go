package security

import (
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// linuxFirewallCheck returns the firewall check for the firewall that
// collectFirewallProfiles found filtering inbound traffic: ufw when active,
// otherwise firewalld when running. Rules loaded straight into iptables or
// nftables aren't evaluated, so they give "unknown"; with no firewall at all
// every risky service is "disabled".
func linuxFirewallCheck(profiles []shared.FirewallProfile) firewallCheck {
	for _, p := range profiles {
		if !p.Enabled {
			continue
		}
		switch p.Name {
		case "ufw":
			if out, err := securityRunCommand("ufw", "status", "verbose"); err == nil {
				if st := parseUFWStatus(out); st.active {
					return st.check(parseUFWAppProfiles(readUFWAppProfiles()))
				}
			}
		case "firewalld":
			if out, err := securityRunCommand("firewall-cmd", "--list-all-zones"); err == nil {
				return firewalldCheck(parseFirewalldZones(out), firewalldServicePorts)
			}
		}
		return constantCheck(firewallUnknown)
	}
	if rawFirewallRules() {
		return constantCheck(firewallUnknown)
	}
	return constantCheck(firewallDisabled)
}

// rawFirewallRules reports whether iptables or nftables has a DROP/REJECT
// rule or policy that no firewall manager accounts for (collectFirewallProfiles
// stops at the first manager it finds, even an inactive ufw).
func rawFirewallRules() bool {
	for _, args := range [][]string{{"iptables", "-L", "-n"}, {"nft", "list", "ruleset"}} {
		if out, err := securityRunCommand(args[0], args[1:]...); err == nil {
			lower := strings.ToLower(out)
			if strings.Contains(lower, "drop") || strings.Contains(lower, "reject") {
				return true
			}
		}
	}
	return false
}

// readUFWAppProfiles returns the contents of ufw's application profiles.
func readUFWAppProfiles() []string {
	files, _ := filepath.Glob(filepath.Join(securityHostRoot, "/etc/ufw/applications.d", "*"))
	var contents []string
	for _, f := range files {
		// #nosec G304 - fixed system directory
		if data, err := os.ReadFile(f); err == nil {
			contents = append(contents, string(data))
		}
	}
	return contents
}

// firewalldServicePorts resolves a firewalld service to its ports: an admin
// definition in /etc/firewalld/services overrides the packaged one.
func firewalldServicePorts(name string) ([]portSpec, bool) {
	if strings.ContainsAny(name, `/\`) || name == "" {
		return nil, false
	}
	for _, dir := range []string{"/etc/firewalld/services", "/usr/lib/firewalld/services"} {
		// #nosec G304 - fixed system directories; name has no path separators
		if data, err := os.ReadFile(filepath.Join(securityHostRoot, dir, name+".xml")); err == nil {
			return parseFirewalldService(data)
		}
	}
	return nil, false
}
