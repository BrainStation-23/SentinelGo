package system

import (
	"encoding/json"
	"fmt"
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
	if serial, ok := serialFromSystemProfiler(); ok {
		return serial
	}
	if serial, ok := serialFromIoreg(); ok {
		return serial
	}
	hostname, _ := os.Hostname()
	return hostname
}

// serialFromSystemProfiler reads the hardware serial number from
// system_profiler's SPHardwareDataType JSON output.
func serialFromSystemProfiler() (string, bool) {
	output, err := shared.RunCommand("system_profiler", "SPHardwareDataType", "-json")
	if err != nil {
		return "", false
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return "", false
	}
	hardware, ok := firstDarwinHardwareItem(result)
	if !ok {
		return "", false
	}
	serial, ok := hardware["serial_number"].(string)
	return serial, ok
}

// firstDarwinHardwareItem returns the first entry of system_profiler's
// SPHardwareDataType array from an already-unmarshaled JSON result.
func firstDarwinHardwareItem(result map[string]any) (map[string]any, bool) {
	hardwareRaw, ok := result["SPHardwareDataType"]
	if !ok {
		return nil, false
	}
	hardwareArr, ok := hardwareRaw.([]any)
	if !ok || len(hardwareArr) == 0 {
		return nil, false
	}
	hardware, ok := hardwareArr[0].(map[string]any)
	return hardware, ok
}

// serialFromIoreg reads IOPlatformSerialNumber from "ioreg -l" output, used
// as a fallback when system_profiler doesn't report a serial number.
func serialFromIoreg() (string, bool) {
	output, err := shared.RunCommand("ioreg", "-l")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(output, "\n") {
		if serial, ok := serialFromIoregLine(line); ok {
			return serial, true
		}
	}
	return "", false
}

// serialFromIoregLine extracts the IOPlatformSerialNumber value from a single
// ioreg -l output line, if present.
func serialFromIoregLine(line string) (string, bool) {
	if !strings.Contains(line, "IOPlatformSerialNumber") {
		return "", false
	}
	parts := strings.Split(line, `"`)
	for i, part := range parts {
		if part == "IOPlatformSerialNumber" && i+2 < len(parts) {
			return parts[i+2], true
		}
	}
	return "", false
}

func getBatteryCondition() string {
	if condition, ok := batteryConditionFromSystemProfiler(); ok {
		return condition
	}
	if condition, ok := batteryConditionFromPmset(); ok {
		return condition
	}
	return "No Battery"
}

// batteryConditionFromSystemProfiler reads battery status via
// system_profiler's SPPowerDataType, returning ok=false when no battery
// information is reported.
func batteryConditionFromSystemProfiler() (string, bool) {
	output, err := shared.RunCommand("system_profiler", "SPPowerDataType", "-json")
	if err != nil || !strings.Contains(output, "BatteryInformation") {
		return "", false
	}
	if status, ok := batteryStatusFromProfilerOutput(output); ok {
		return status, true
	}
	if strings.Contains(output, "AC Power") {
		return "Charging", true
	}
	return "", false
}

// batteryStatusFromProfilerOutput scans system_profiler output line by line
// for a BatteryStatus/State of Charge field.
func batteryStatusFromProfilerOutput(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		if status, ok := batteryStatusFromLine(line); ok {
			return status, true
		}
	}
	return "", false
}

// batteryStatusFromLine extracts the value of a "BatteryStatus" or
// "State of Charge" JSON line, if present and non-empty.
func batteryStatusFromLine(line string) (string, bool) {
	if !strings.Contains(line, "BatteryStatus") && !strings.Contains(line, "State of Charge") {
		return "", false
	}
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return "", false
	}
	status := strings.Trim(strings.TrimSpace(parts[1]), `",`)
	return status, status != ""
}

// batteryConditionFromPmset reads battery percentage via "pmset -g batt",
// returning ok=false when no battery is reported.
func batteryConditionFromPmset() (string, bool) {
	output, err := shared.RunCommand("pmset", "-g", "batt")
	if err != nil {
		return "", false
	}
	if strings.Contains(output, "Battery Power") {
		if percent, ok := batteryPercentFromPmsetOutput(output); ok {
			return percent, true
		}
	}
	if strings.Contains(output, "AC Power") {
		return "Charging", true
	}
	return "", false
}

// batteryPercentFromPmsetOutput scans pmset output line by line for a
// percentage field.
func batteryPercentFromPmsetOutput(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		if percent, ok := batteryPercentFromLine(line); ok {
			return percent, true
		}
	}
	return "", false
}

// batteryPercentFromLine extracts "<label> <NN%>" from a pmset battery line.
func batteryPercentFromLine(line string) (string, bool) {
	if !strings.Contains(line, "%") {
		return "", false
	}
	fields := strings.Fields(line)
	for i, field := range fields {
		if strings.HasSuffix(field, "%") && i > 0 {
			return fields[i-1] + " " + field, true
		}
	}
	return "", false
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
	var version, buildVersion string
	if out, err := shared.RunCommand("sw_vers", "-productVersion"); err == nil {
		version = strings.TrimSpace(out)
	}
	if out, err := shared.RunCommand("sw_vers", "-productName"); err == nil {
		osInfo.OSName = strings.TrimSpace(out)
	}
	if out, err := shared.RunCommand("sw_vers", "-buildVersion"); err == nil {
		buildVersion = strings.TrimSpace(out)
	}

	// Combine version and build version into full version string
	if version != "" && buildVersion != "" {
		osInfo.OSVersion = fmt.Sprintf("%s (%s)", version, buildVersion)
	} else if version != "" {
		osInfo.OSVersion = version
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
