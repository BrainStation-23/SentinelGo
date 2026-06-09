package system

import (
	"encoding/json"
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getHardwareModel() string {
	if output, err := shared.RunCommand("system_profiler", "SPHardwareDataType", "-json"); err == nil {
		if model := parseDarwinHardwareModel(output); model != "" {
			return model
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getSerialNumber() string {
	if output, err := shared.RunCommand("system_profiler", "SPHardwareDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if hardwareRaw, ok := result["SPHardwareDataType"]; ok {
				if hardwareArr, ok := hardwareRaw.([]any); ok && len(hardwareArr) > 0 {
					if hardware, ok := hardwareArr[0].(map[string]any); ok {
						if serial, ok := hardware["serial_number"].(string); ok {
							return serial
						}
					}
				}
			}
		}
	}
	if output, err := shared.RunCommand("ioreg", "-l"); err == nil {
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, `"`)
				for i, part := range parts {
					if part == "IOPlatformSerialNumber" && i+2 < len(parts) {
						return parts[i+2]
					}
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getBatteryCondition() string {
	if output, err := shared.RunCommand("system_profiler", "SPPowerDataType", "-json"); err == nil {
		if strings.Contains(output, "BatteryInformation") {
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, "BatteryStatus") || strings.Contains(line, "State of Charge") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						status := strings.Trim(strings.TrimSpace(parts[1]), `",`)
						if status != "" {
							return status
						}
					}
				}
			}
			if strings.Contains(output, "AC Power") {
				return "Charging"
			}
		}
	}
	if output, err := shared.RunCommand("pmset", "-g", "batt"); err == nil {
		if strings.Contains(output, "Battery Power") {
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, "%") {
					fields := strings.Fields(line)
					for i, field := range fields {
						if strings.HasSuffix(field, "%") && i > 0 {
							return fields[i-1] + " " + field
						}
					}
				}
			}
		}
		if strings.Contains(output, "AC Power") {
			return "Charging"
		}
	}
	return "No Battery"
}

func getFQDN() string {
	if output, err := shared.RunCommand("hostname", "-f"); err == nil {
		if fqdn := strings.TrimSpace(output); fqdn != "" {
			return fqdn
		}
	}
	h, _ := os.Hostname()
	return h
}

func getChassisType() string {
	return parseDarwinChassisType(getHardwareModel())
}

func getOSInformation() shared.OSInformation {
	osInfo := osInfoBase()
	if out, err := shared.RunCommand("sw_vers", "-productVersion"); err == nil {
		osInfo.OSVersion = strings.TrimSpace(out)
	}
	if out, err := shared.RunCommand("sw_vers", "-productName"); err == nil {
		osInfo.OSName = strings.TrimSpace(out)
	}
	if out, err := shared.RunCommand("sw_vers", "-buildVersion"); err == nil {
		osInfo.OSServicePack = strings.TrimSpace(out)
	}
	osInfo.OSType = "macOS"
	if osInfo.OSName == "" {
		osInfo.OSName = "darwin"
	}
	return osInfo
}

func getFirmwareInfo() (firmwareType, vendor, version string) {
	firmwareType = "UEFI"
	vendor = "Apple"
	output, err := shared.RunCommand("system_profiler", "SPHardwareDataType", "-json")
	if err != nil {
		return
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return
	}
	hwArr, ok := result["SPHardwareDataType"].([]any)
	if !ok || len(hwArr) == 0 {
		return
	}
	hwItem, ok := hwArr[0].(map[string]any)
	if !ok {
		return
	}
	if v, ok := hwItem["boot_rom_version"].(string); ok {
		version = v
	}
	return
}

func getTPMVersion() string {
	output, err := shared.RunCommand("system_profiler", "SPiBridgeDataType", "-json")
	if err != nil {
		return ""
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return ""
	}
	if bridgeRaw, ok := result["SPiBridgeDataType"]; ok {
		if bridgeArr, ok := bridgeRaw.([]any); ok && len(bridgeArr) > 0 {
			if bridgeItem, ok := bridgeArr[0].(map[string]any); ok {
				if v, ok := bridgeItem["ibridge_model_name"].(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}
