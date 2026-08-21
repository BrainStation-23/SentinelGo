package protection

import (
	"encoding/json"
	"strings"
)

// parseNetshFirewall extracts profile states from
// `netsh advfirewall show allprofiles state`.
//
// The output is a sequence of "<Name> Profile Settings:" headers each followed
// by a "State   ON|OFF" line. Parsing pairs rather than counting lines means a
// localised or reordered output degrades to fewer profiles instead of
// mismatched ones.
func parseNetshFirewall(output string) []Profile {
	var profiles []Profile
	var current string

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "Profile Settings:") {
			current = strings.TrimSpace(strings.TrimSuffix(line, "Profile Settings:"))
			continue
		}
		if current == "" || !strings.HasPrefix(strings.ToLower(line), "state") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		profiles = append(profiles, Profile{
			Name:    current,
			Enabled: strings.EqualFold(fields[len(fields)-1], "ON"),
		})
		current = ""
	}
	return profiles
}

// defenderStatus is the Get-MpComputerStatus projection this collector reads.
//
// Both fields are pointers so an absent property stays distinguishable from a
// present false: reporting "real-time protection disabled" because a property
// was missing would be a fabricated critical security finding.
type defenderStatus struct {
	RealTimeProtectionEnabled *bool `json:"RealTimeProtectionEnabled"`
	IsTamperProtected         *bool `json:"IsTamperProtected"`
}

// parseDefenderStatus decodes the ConvertTo-Json output of Get-MpComputerStatus.
func parseDefenderStatus(output string) (defenderStatus, bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return defenderStatus{}, false
	}
	var s defenderStatus
	if err := json.Unmarshal([]byte(trimmed), &s); err != nil {
		return defenderStatus{}, false
	}
	return s, true
}

// controlFromBool maps an optional platform boolean to a control state, leaving
// a missing value as "unknown" rather than inferring "disabled".
func controlFromBool(v *bool, product string) Control {
	if v == nil {
		return Control{State: StateUnknown, Product: product}
	}
	if *v {
		return Control{State: StateEnabled, Product: product}
	}
	return Control{State: StateDisabled, Product: product}
}

// parseUFWStatus reads the first line of `ufw status`, which is
// "Status: active" or "Status: inactive".
func parseUFWStatus(output string) (Profile, bool) {
	first := strings.ToLower(strings.TrimSpace(strings.SplitN(output, "\n", 2)[0]))
	if !strings.HasPrefix(first, "status:") {
		return Profile{}, false
	}
	active := strings.Contains(first, "active") && !strings.Contains(first, "inactive")
	return Profile{Name: "ufw", Enabled: active}, true
}

// parseFirewalldState reads `firewall-cmd --state`, which prints "running" or
// "not running".
func parseFirewalldState(output string) Profile {
	return Profile{
		Name:    "firewalld",
		Enabled: strings.TrimSpace(strings.ToLower(output)) == "running",
	}
}

// parseIptablesRules reports iptables as a firewall only when it actually
// filters something. An all-ACCEPT ruleset is not a firewall, and calling it one
// would mask a genuinely unprotected host.
func parseIptablesRules(output string) Profile {
	lower := strings.ToLower(output)
	return Profile{
		Name:    "iptables",
		Enabled: strings.Contains(lower, "drop") || strings.Contains(lower, "reject"),
	}
}

// parseSocketFilterFW reads macOS's
// `socketfilterfw --getglobalstate`, which prints
// "Firewall is enabled. (State = 1)" or "Firewall is disabled. (State = 0)".
func parseSocketFilterFW(output string) Profile {
	lower := strings.ToLower(output)
	return Profile{
		Name:    "Application Firewall",
		Enabled: strings.Contains(lower, "enabled") && !strings.Contains(lower, "disabled"),
	}
}
