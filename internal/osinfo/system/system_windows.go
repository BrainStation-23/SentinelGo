package system

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getHardwareModel() string {
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model"); err == nil {
		if model := strings.TrimSpace(output); model != "" {
			return model
		}
	}
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer"); err == nil {
		if manufacturer := strings.TrimSpace(output); manufacturer != "" {
			return manufacturer
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getSerialNumber() string {
	type candidate struct {
		cmd     string
		invalid []string
	}
	candidates := []candidate{
		{
			"Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber",
			[]string{"To be filled by O.E.M.", "Default string", "System Serial Number"},
		},
		{
			"Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty IdentifyingNumber",
			[]string{"To be filled by O.E.M.", "Default string"},
		},
		{
			"Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber",
			[]string{"To be filled by O.E.M.", "Default string"},
		},
	}
	for _, c := range candidates {
		output, err := shared.RunCommand("powershell", "-NoProfile", "-Command", c.cmd)
		if err != nil {
			continue
		}
		serial := strings.TrimSpace(output)
		invalid := false
		for _, bad := range c.invalid {
			if serial == bad {
				invalid = true
				break
			}
		}
		if !invalid && serial != "" {
			return serial
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getBatteryCondition() string {
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -ClassName Win32_Battery | Select-Object -ExpandProperty BatteryStatus"); err == nil {
		if status := parseBatteryStatusCode(output); status != "" {
			return status
		}
	}
	return "Unknown"
}

func getFQDN() string {
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"[System.Net.Dns]::GetHostEntry('').HostName"); err == nil {
		if fqdn := strings.TrimSpace(output); fqdn != "" {
			return fqdn
		}
	}
	h, _ := os.Hostname()
	return h
}

func getChassisType() string {
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_SystemEnclosure | Select-Object -ExpandProperty ChassisTypes"); err == nil {
		val := strings.Trim(strings.TrimSpace(output), "{} \r\n")
		parts := strings.Fields(val)
		if len(parts) > 0 {
			var n int
			if _, err := fmt.Sscanf(parts[0], "%d", &n); err == nil {
				if result := parseWindowsChassisCode(n); result != "" {
					return result
				}
			}
		}
	}
	return "Other"
}

func getOSInformation() shared.OSInformation {
	osInfo := osInfoBase()

	// Single PowerShell call: combines Win32_OperatingSystem, the registry CurrentVersion
	// hive (for UBR = Update Build Revision and DisplayVersion e.g. "25H2"), timezone,
	// locale, and UI language — avoids multiple subprocess round-trips.
	const ps = `$os = Get-CimInstance Win32_OperatingSystem;` +
		`$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';` +
		`$tz = Get-TimeZone;` +
		`[PSCustomObject]@{` +
		`Caption=''+$os.Caption;` +
		`Version=''+$os.Version+'.'+$reg.UBR;` +
		`DisplayVersion=''+$reg.DisplayVersion;` +
		`Locale=(Get-WinSystemLocale).Name;` +
		`Language=(Get-UICulture).Name;` +
		`TimeZoneId=$tz.Id;` +
		`TimeZoneOffset=[int]$tz.BaseUtcOffset.TotalMinutes` +
		`} | ConvertTo-Json -Compress`

	if out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", ps); err == nil {
		name, version, displayVer, locale, language, tzID, tzOffset :=
			parseWindowsOSInfoExtendedJSON(out)
		if name != "" {
			osInfo.OSName = name
		}
		if version != "" {
			osInfo.OSVersion = version
		}
		if displayVer != "" {
			osInfo.OSServicePack = displayVer
		}
		if locale != "" {
			osInfo.OSLocale = locale
		}
		if language != "" {
			osInfo.OSLanguage = language
		}
		if tzID != "" {
			osInfo.OSTimeZone = tzID
			osInfo.OSTimeZoneOffsetMinutes = tzOffset
		}
	}

	osInfo.OSType = "Microsoft Windows"
	if osInfo.OSName == "" {
		osInfo.OSName = "windows"
	}
	return osInfo
}

func getFirmwareInfo() (firmwareType, vendor, version string) {
	firmwareType = "UEFI"
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion,Manufacturer | ConvertTo-Json")
	if err != nil {
		return
	}
	output = strings.TrimSpace(output)
	var obj map[string]any
	var arr []map[string]any
	if json.Unmarshal([]byte(output), &arr) == nil && len(arr) > 0 {
		obj = arr[0]
	} else {
		_ = json.Unmarshal([]byte(output), &obj)
	}
	if obj != nil {
		if v, ok := obj["SMBIOSBIOSVersion"].(string); ok {
			version = v
		}
		if v, ok := obj["Manufacturer"].(string); ok {
			vendor = v
		}
	}
	return
}
