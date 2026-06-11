package security

import (
	"encoding/json"
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

const avCrowdStrikeFalcon = "CrowdStrike Falcon"

// knownAVApps maps known AV installation paths to product names.
var knownAVApps = []struct {
	path string
	name string
}{
	{"/Applications/Malwarebytes.app", "Malwarebytes"},
	{"/Applications/Falcon.app", avCrowdStrikeFalcon},
	{"/Library/CS/falconctl", avCrowdStrikeFalcon},
	{"/Library/Application Support/CrowdStrike/Falcon", avCrowdStrikeFalcon},
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
		AntivirusProducts:    collectAV(),
		FirewallEnabled:      enabled,
		FirewallProfiles:     profiles,
		CoreIsolation:        collectCoreIsolation(),
		SecureBootEnabled:    collectSecureBoot(),
		ListeningPorts:       collectListeningPorts(),
		USBMassStorageEnabled: collectUSBMassStorage(),
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

// collectUSBMassStorage checks whether USB mass storage is permitted on macOS.
// On MDM-managed devices, plutil can read the applicationaccess managed preference
// plist and report the allowUSBRestricted policy directly. On unmanaged devices,
// a loaded IOUSBMassStorageClass kext confirms mass storage is active; otherwise
// the state cannot be determined without root or MDM access.
func collectUSBMassStorage() string {
	if state := usbStateFromMDM(); state != "" {
		return state
	}
	if kstat, err := shared.RunCommand("kextstat"); err == nil {
		if strings.Contains(kstat, "IOUSBMassStorageClass") {
			return "enabled"
		}
	}
	return "unknown"
}

// usbStateFromMDM reads the allowUSBRestricted key from the MDM-managed
// applicationaccess preference plist. Returns "" when the plist is absent,
// unreadable, or does not contain the key.
func usbStateFromMDM() string {
	out, err := shared.RunCommand("plutil", "-convert", "json", "-o", "-",
		"/Library/Managed Preferences/com.apple.applicationaccess.plist")
	if err != nil {
		return ""
	}
	return parseAllowUSBRestrictedJSON(out)
}

// parseAllowUSBRestrictedJSON extracts the allowUSBRestricted bool from a JSON
// string produced by plutil. Returns "enabled", "disabled", or "" if the key is
// absent or the input is not valid JSON.
func parseAllowUSBRestrictedJSON(jsonStr string) string {
	var prefs map[string]interface{}
	if json.Unmarshal([]byte(jsonStr), &prefs) != nil {
		return ""
	}
	v, ok := prefs["allowUSBRestricted"]
	if !ok {
		return ""
	}
	allowed, ok := v.(bool)
	if !ok {
		return ""
	}
	if allowed {
		return "enabled"
	}
	return "disabled"
}
