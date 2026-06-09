package system

// parse.go — pure string-parsing helpers shared across platform implementations.
// No OS build suffix: compiles on every platform and unit-testable without OS commands.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseOSQueryVersion extracts the version string from `osqueryi --version` output.
// Expected format: "osquery version X.Y.Z" (may have trailing whitespace or extra lines).
func parseOSQueryVersion(output string) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		for i, part := range parts {
			if part == "version" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

// parseBootRelative converts a duration since boot to a human-readable relative string.
func parseBootRelative(d time.Duration) string {
	if days := int(d.Hours() / 24); days > 0 {
		return fmt.Sprintf("%d days ago", days)
	}
	if hours := int(d.Hours()); hours > 0 {
		return fmt.Sprintf("%d hours ago", hours)
	}
	if minutes := int(d.Minutes()); minutes > 0 {
		return fmt.Sprintf("%d minutes ago", minutes)
	}
	return "Recently"
}

// parseBatteryStatusCode maps a Win32_Battery BatteryStatus numeric code to a string.
// Returns "" for unrecognised codes so callers can detect "no battery / unknown".
func parseBatteryStatusCode(code string) string {
	switch strings.TrimSpace(code) {
	case "1":
		return "Discharging"
	case "2":
		return "AC Power"
	case "3":
		return "Fully Charged"
	case "4":
		return "Low"
	case "5":
		return "Critical"
	case "6":
		return "Charging"
	case "7":
		return "Undefined"
	}
	return ""
}

// parseWindowsChassisCode maps a Win32_SystemEnclosure ChassisTypes integer to a
// chassis category string. Returns "" for unrecognised codes.
func parseWindowsChassisCode(n int) string {
	switch n {
	case 3, 4, 5, 6, 7, 15, 16:
		return "Desktop"
	case 8, 9, 10, 11, 12, 14, 18, 21:
		return "Notebook"
	case 17, 23:
		return "Server"
	case 30, 31, 32:
		return "Tablet"
	}
	return ""
}

// parseWindowsOSInfoJSON parses Win32_OperatingSystem JSON (Caption, Version, BuildNumber).
func parseWindowsOSInfoJSON(output string) (name, version, build string) {
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil {
		return
	}
	if v, ok := result["Caption"].(string); ok {
		name = strings.TrimSpace(v)
	}
	if v, ok := result["Version"].(string); ok {
		version = strings.TrimSpace(v)
	}
	if v, ok := result["BuildNumber"]; ok {
		build = fmt.Sprintf("%v", v)
	}
	return
}

// parseWindowsOSInfoExtendedJSON parses the comprehensive Windows OS info JSON produced by
// a single PowerShell command that combines Win32_OperatingSystem, the CurrentVersion
// registry hive (for UBR and DisplayVersion), timezone, and locale.
//
// Expected keys: Caption, Version (already includes UBR suffix), DisplayVersion,
// Locale, Language, TimeZoneId, TimeZoneOffset (int minutes from UTC).
func parseWindowsOSInfoExtendedJSON(output string) (name, version, displayVersion, locale, language, tzID string, tzOffset int) {
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil {
		return
	}
	getString := func(key string) string {
		if v, ok := result[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	name = getString("Caption")
	version = getString("Version")
	displayVersion = getString("DisplayVersion")
	locale = getString("Locale")
	language = getString("Language")
	tzID = getString("TimeZoneId")
	if v, ok := result["TimeZoneOffset"].(float64); ok {
		tzOffset = int(v)
	}
	return
}

// parseOSReleaseContent parses /etc/os-release and returns the pretty name and version.
// Both quoted and unquoted values are handled.
func parseOSReleaseContent(content string) (name, version string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"`)
		}
	}
	return
}

// containsVM reports whether a (lowercased) product name string indicates a virtual machine.
func containsVM(s string) bool {
	for _, kw := range []string{"virtualbox", "vmware", "qemu", "kvm", "virtual machine"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// parseLinuxChassisType converts a chassis_type file value and product_name to a chassis
// category string. Returns "" when the type code is unrecognised or unparseable.
func parseLinuxChassisType(typeCode, productName string) string {
	n, err := strconv.Atoi(strings.TrimSpace(typeCode))
	if err != nil {
		return ""
	}
	switch {
	case n >= 3 && n <= 7:
		if containsVM(strings.ToLower(productName)) {
			return "VM"
		}
		return "Desktop"
	case n >= 8 && n <= 14:
		return "Notebook"
	case n == 17 || n == 23 || n == 28 || n == 29:
		return "Server"
	case n >= 30 && n <= 32:
		return "Tablet"
	}
	return ""
}

// parseDarwinChassisType returns the chassis category for a macOS hardware model name.
func parseDarwinChassisType(model string) string {
	ml := strings.ToLower(model)
	if strings.Contains(ml, "macbook") {
		return "Notebook"
	}
	if strings.Contains(ml, "mac mini") || strings.Contains(ml, "imac") ||
		strings.Contains(ml, "mac pro") || strings.Contains(ml, "mac studio") {
		return "Desktop"
	}
	return "Other"
}

// parseDarwinHardwareModel extracts model_name (or machine_name on older macOS) from
// system_profiler SPHardwareDataType JSON output.
func parseDarwinHardwareModel(output string) string {
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return ""
	}
	hwRaw, ok := result["SPHardwareDataType"]
	if !ok {
		return ""
	}
	hwArr, ok := hwRaw.([]any)
	if !ok || len(hwArr) == 0 {
		return ""
	}
	hw, ok := hwArr[0].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := hw["model_name"].(string); ok && v != "" {
		return v
	}
	if v, ok := hw["machine_name"].(string); ok && v != "" {
		return v
	}
	return ""
}
