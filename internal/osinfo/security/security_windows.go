package security

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

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
		AntivirusProducts:     collectAV(),
		FirewallEnabled:       enabled,
		FirewallProfiles:      profiles,
		CoreIsolation:         collectCoreIsolation(),
		SecureBootEnabled:     collectSecureBoot(),
		ListeningPorts:        collectListeningPorts(),
		USBMassStorageEnabled: collectUSBMassStorage(),
	}
}

// collectUSBMassStorage checks whether the USB Mass Storage driver (USBSTOR) is
// enabled via its service start type in the registry.
// Group Policy / MDM sets Start=4 (SERVICE_DISABLED) to block removable drives.
func collectUSBMassStorage() string {
	output, err := shared.RunCommand("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start")
	if err != nil {
		return "unknown"
	}
	return usbStorStartToState(parseRegDWORD(output, "Start"))
}

// usbStorStartToState maps a USBSTOR service Start DWORD value to a state string.
// Start=4 is SERVICE_DISABLED; 0–3 are boot/system/auto/demand (all permit the driver to load).
// parseRegDWORD returns -1 when the value is absent; any other unexpected value → "unknown".
func usbStorStartToState(v int) string {
	switch v {
	case 4:
		return "disabled"
	case 0, 1, 2, 3:
		return "enabled"
	default:
		return "unknown"
	}
}

// collectAV queries Windows Security Center 2 for registered antivirus products.
func collectAV() []shared.AntivirusProduct {
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress")
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}
	return parseAVProductsJSON(output)
}

// parseAVProductsJSON decodes ConvertTo-Json output from the SecurityCenter2 query.
// PowerShell returns a JSON object when there is exactly one product, or an array for multiple.
func parseAVProductsJSON(output string) []shared.AntivirusProduct {
	output = strings.TrimSpace(output)
	var raw []map[string]interface{}
	var single map[string]interface{}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		if err2 := json.Unmarshal([]byte(output), &single); err2 != nil {
			return nil
		}
		raw = []map[string]interface{}{single}
	}

	var products []shared.AntivirusProduct
	for _, item := range raw {
		name, _ := item["displayName"].(string)
		if name == "" {
			continue
		}
		var state float64
		switch v := item["productState"].(type) {
		case float64:
			state = v
		}
		productState := int(state)

		// productState bitmask:
		//   bits 12-15 (masked): 1 = protection enabled
		//   bits  4-7  (masked): 0 = definitions up-to-date
		enabled := "unknown"
		upToDate := "unknown"
		if productState > 0 {
			if (productState>>12)&0x0F == 1 {
				enabled = "enabled"
			} else {
				enabled = "disabled"
			}
			if (productState>>4)&0x0F == 0 {
				upToDate = "yes"
			} else {
				upToDate = "no"
			}
		}
		products = append(products, shared.AntivirusProduct{
			Name:     strings.TrimSpace(name),
			Enabled:  enabled,
			UpToDate: upToDate,
			Source:   "SecurityCenter2",
		})
	}
	return products
}

// collectFirewallProfiles parses netsh output for Domain/Private/Public profile states.
func collectFirewallProfiles() []shared.FirewallProfile {
	output, err := shared.RunCommand("netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return nil
	}
	return parseNetshFirewall(output)
}

// parseNetshFirewall extracts firewall profile states from netsh advfirewall output.
// Example line sequence: "Domain Profile Settings:\n...\nState  ON\n"
func parseNetshFirewall(output string) []shared.FirewallProfile {
	var profiles []shared.FirewallProfile
	var current string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "Profile Settings:") {
			current = strings.TrimSuffix(line, " Profile Settings:")
		} else if strings.HasPrefix(strings.ToLower(line), "state") && current != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				enabled := strings.EqualFold(parts[len(parts)-1], "ON")
				profiles = append(profiles, shared.FirewallProfile{
					Name:    current,
					Enabled: enabled,
				})
				current = ""
			}
		}
	}
	return profiles
}

// collectCoreIsolation reads Windows Device Guard / HVCI registry values.
func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		MemoryIntegrityEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`,
			"Enabled"),
		VBSEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`,
			"EnableVirtualizationBasedSecurity"),
		CredentialGuardEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard`,
			"Enabled"),
	}
}

// queryRegistryBool returns true when the named DWORD registry value equals 1.
func queryRegistryBool(keyPath, valueName string) bool {
	output, err := shared.RunCommand("reg", "query", keyPath, "/v", valueName)
	if err != nil {
		return false
	}
	return parseRegDWORD(output, valueName) == 1
}

// parseRegDWORD extracts the integer value of a REG_DWORD entry from reg query output.
// Expected format: "    ValueName    REG_DWORD    0x1"
func parseRegDWORD(output, valueName string) int {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), strings.ToLower(valueName)) {
			continue
		}
		parts := strings.Fields(line)
		for i, p := range parts {
			if strings.EqualFold(p, "REG_DWORD") && i+1 < len(parts) {
				var n int
				if _, err := fmt.Sscanf(parts[i+1], "0x%x", &n); err == nil {
					return n
				}
				if _, err := fmt.Sscanf(parts[i+1], "%d", &n); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

// collectSecureBoot reads the UEFI Secure Boot state from the registry.
func collectSecureBoot() string {
	output, err := shared.RunCommand("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`,
		"/v", "UEFISecureBootEnabled")
	if err != nil {
		return "unknown"
	}
	switch parseRegDWORD(output, "UEFISecureBootEnabled") {
	case 1:
		return "enabled"
	case 0:
		return "disabled"
	default:
		return "unknown"
	}
}
