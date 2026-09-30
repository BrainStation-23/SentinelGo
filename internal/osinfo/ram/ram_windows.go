package ram

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getRAMs() shared.RAMInfo {
	output, err := shared.RunPowerShell(
		"Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,PartNumber,Capacity,ConfiguredClockSpeed,SerialNumber,SMBIOSMemoryType,FormFactor,DeviceLocator | ConvertTo-Json")
	if err != nil {
		return shared.RAMInfo{}
	}

	rams, totalBytes := parseWindowsMemoryItems(strings.TrimSpace(output))

	return shared.RAMInfo{
		TotalCapacity: totalBytes,
		RAMs:          rams,
	}
}

// parseWindowsMemoryItems unmarshals the Get-CimInstance JSON output, which
// PowerShell emits as a single object (one stick) or an array (multiple
// sticks).
func parseWindowsMemoryItems(output string) ([]shared.RAMStick, uint64) {
	var rams []shared.RAMStick
	var totalBytes uint64

	var arr []map[string]any
	if json.Unmarshal([]byte(output), &arr) == nil && len(arr) > 0 {
		for _, item := range arr {
			if ram, sizeBytes, ok := parseWindowsRAMStick(item); ok {
				rams = append(rams, ram)
				totalBytes += sizeBytes
			}
		}
		return rams, totalBytes
	}

	var obj map[string]any
	if json.Unmarshal([]byte(output), &obj) == nil {
		if ram, sizeBytes, ok := parseWindowsRAMStick(obj); ok {
			rams = append(rams, ram)
			totalBytes += sizeBytes
		}
	}

	return rams, totalBytes
}

// parseWindowsRAMStick parses one Win32_PhysicalMemory CIM instance into a
// RAM stick. ok is false when the entry reports no capacity.
func parseWindowsRAMStick(item map[string]any) (shared.RAMStick, uint64, bool) {
	ram := shared.RAMStick{}
	var sizeBytes uint64

	if v, ok := item["Manufacturer"].(string); ok {
		ram.Manufacturer = normalizeRAMManufacturer(v)
	}
	if v, ok := item["PartNumber"].(string); ok {
		ram.Name = strings.TrimSpace(v)
	}
	if v, ok := item["Capacity"].(float64); ok && v > 0 {
		sizeBytes = uint64(v)
		ram.Capacity = sizeBytes
	}
	if v, ok := item["ConfiguredClockSpeed"].(float64); ok {
		ram.ClockSpeedMHz = int(v)
	}
	if v, ok := item["SerialNumber"].(string); ok {
		ram.Serial = strings.TrimSpace(v)
	}
	// SMBIOSMemoryType is the authoritative DDR generation from SMBIOS table 17
	if v, ok := item["SMBIOSMemoryType"].(float64); ok {
		ram.ArchitectureType = smbiosTypeToString(int(v))
	}
	if v, ok := item["FormFactor"].(float64); ok {
		ram.FormFactor = windowsFormFactor(int(v))
	}
	if v, ok := item["DeviceLocator"].(string); ok {
		ram.Slot = strings.TrimSpace(v)
	}

	return ram, sizeBytes, sizeBytes > 0
}

// smbiosTypeToString maps SMBIOS table 17 memory type codes to DDR generation strings.
func smbiosTypeToString(t int) string {
	switch t {
	case 35:
		return "LPDDR5"
	case 34:
		return "DDR5"
	case 33:
		return "HBM2"
	case 32:
		return "HBM"
	case 30:
		return "LPDDR4"
	case 29:
		return "LPDDR3"
	case 28:
		return "LPDDR2"
	case 27:
		return "LPDDR"
	case 26:
		return "DDR4"
	case 24:
		return "DDR3"
	case 22:
		return "DDR2 FB-DIMM"
	case 21:
		return "DDR2"
	case 20:
		return "DDR"
	case 17:
		return "SDRAM"
	default:
		return "Unknown"
	}
}

// windowsFormFactor maps Win32_PhysicalMemory FormFactor codes to form factor strings.
func windowsFormFactor(code int) string {
	switch code {
	case 8:
		return "DIMM"
	case 12:
		return "SO-DIMM"
	case 13:
		return "Micro-DIMM"
	case 7, 15:
		return "SIMM"
	case 14:
		return "RIMM"
	default:
		return ""
	}
}
