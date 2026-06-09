package security

import (
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// knownAVApps maps known AV installation paths to product names.
var knownAVApps = []struct {
	path string
	name string
}{
	{"/Applications/Malwarebytes.app", "Malwarebytes"},
	{"/Applications/Falcon.app", "CrowdStrike Falcon"},
	{"/Library/CS/falconctl", "CrowdStrike Falcon"},
	{"/Library/Application Support/CrowdStrike/Falcon", "CrowdStrike Falcon"},
	{"/Applications/SentinelOne Extensions.app", "SentinelOne"},
	{"/Applications/ESET Endpoint Security.app", "ESET Endpoint Security"},
	{"/Applications/Sophos/Sophos Anti-Virus.app", "Sophos AV"},
	{"/Library/Sophos Anti-Virus Extension", "Sophos AV"},
}

func collectSecurity() shared.SecurityInfo {
	profiles := collectFirewallProfiles()
	enabled := false
	for _, p := range profiles {
		if p.Enabled {
			enabled = true
			break
		}
	}
	return shared.SecurityInfo{
		AntivirusProducts: collectAV(),
		FirewallEnabled:   enabled,
		FirewallProfiles:  profiles,
		CoreIsolation:     collectCoreIsolation(),
		SecureBootEnabled: collectSecureBoot(),
		ListeningPorts:    collectListeningPorts(),
	}
}

// collectAV checks for known AV app bundles and reports Gatekeeper status.
func collectAV() []shared.AntivirusProduct {
	var products []shared.AntivirusProduct
	seen := map[string]bool{}

	for _, app := range knownAVApps {
		if seen[app.name] {
			continue
		}
		if _, err := os.Stat(app.path); err == nil {
			seen[app.name] = true
			products = append(products, shared.AntivirusProduct{
				Name:     app.name,
				Enabled:  "unknown",
				UpToDate: "unknown",
				Source:   "process",
			})
		}
	}

	// Gatekeeper: macOS built-in application assessment.
	gkEnabled := "disabled"
	if output, err := shared.RunCommand("spctl", "--status"); err == nil {
		if strings.Contains(strings.ToLower(output), "assessments enabled") {
			gkEnabled = "enabled"
		}
	}
	products = append(products, shared.AntivirusProduct{
		Name:     "Gatekeeper",
		Enabled:  gkEnabled,
		UpToDate: "unknown",
		Source:   "gatekeeper",
	})

	return products
}

// collectFirewallProfiles queries the macOS Application Firewall state.
func collectFirewallProfiles() []shared.FirewallProfile {
	output, err := shared.RunCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil {
		return nil
	}
	lower := strings.ToLower(strings.TrimSpace(output))
	enabled := strings.Contains(lower, "enabled")
	return []shared.FirewallProfile{{Name: "Application Firewall", Enabled: enabled}}
}

func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		SIPEnabled: collectSIP(),
	}
}

// collectSIP reports the System Integrity Protection state via csrutil.
func collectSIP() string {
	output, err := shared.RunCommand("csrutil", "status")
	if err != nil {
		return "unknown"
	}
	lower := strings.ToLower(strings.TrimSpace(output))
	if strings.Contains(lower, "enabled") {
		return "enabled"
	}
	if strings.Contains(lower, "disabled") {
		return "disabled"
	}
	return "unknown"
}

// collectSecureBoot infers Secure Boot state from the iBridge/T2 data type.
// On T2 and Apple Silicon, Secure Boot is always present; the active security
// policy ("Full Security", "Reduced Security", "No Security") determines enforcement.
func collectSecureBoot() string {
	output, err := shared.RunCommand("system_profiler", "SPiBridgeDataType")
	if err != nil {
		return "unknown"
	}
	lower := strings.ToLower(output)
	if strings.Contains(lower, "no security") {
		return "disabled"
	}
	if strings.Contains(lower, "full security") || strings.Contains(lower, "reduced security") {
		return "enabled"
	}
	// T2/Apple Silicon detected but security policy not explicitly stated.
	if strings.Contains(lower, "bridge os") || strings.Contains(lower, "apple t") {
		return "enabled"
	}
	return "unknown"
}
