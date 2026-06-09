package gpu

import (
	"encoding/json"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// formatVRAMBytes converts a raw VRAM byte count from Win32_VideoController.AdapterRAM
// to a human-readable string. AdapterRAM is a uint32 WMI field, so values ≥ 4 GB overflow
// and are returned near the uint32 ceiling instead of their true size.
func formatVRAMBytes(bytes int64) string {
	const uint32Near4GB = 4*1024*1024*1024 - 1024*1024
	switch {
	case bytes >= uint32Near4GB:
		return ">= 4 GB"
	case bytes >= 1024*1024*1024:
		return strconv.FormatInt(bytes/(1024*1024*1024), 10) + " GB"
	case bytes >= 1024*1024:
		return strconv.FormatInt(bytes/(1024*1024), 10) + " MB"
	default:
		return strconv.FormatInt(bytes/1024, 10) + " KB"
	}
}

// windowsGPUArchitecture returns "Discrete" or "Integrated" from WMI VideoMemoryType
// (3=VRAM/discrete, 4=DRAM/integrated), falling back to manufacturer name heuristics
// when VideoMemoryType is absent or ambiguous (1=Other, 2=Unknown).
func windowsGPUArchitecture(vmt int, manufacturer string) string {
	switch vmt {
	case 3:
		return "Discrete"
	case 4:
		return "Integrated"
	}
	mLow := strings.ToLower(manufacturer)
	switch {
	case strings.Contains(mLow, "intel"), strings.Contains(mLow, "apple"):
		return "Integrated"
	case strings.Contains(mLow, "nvidia"),
		strings.Contains(mLow, "amd"),
		strings.Contains(mLow, "ati"),
		strings.Contains(mLow, "advanced micro"):
		return "Discrete"
	}
	return "Unknown"
}

func getGPUs() []shared.GPU {
	var gpus []shared.GPU

	// VideoMemoryType: 3=VRAM (dedicated/discrete), 4=DRAM (shared/integrated).
	// AdapterRAM is a uint32 WMI field, capped at ~4 GB; may underreport high-VRAM GPUs.
	// PNPDeviceID is the correct per-adapter hardware identifier.
	// Status is the WMI device health string ("OK", "Error", "Degraded", etc.).
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,"+
			"@{n='DriverDate';e={if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}else{''}}},"+
			"VideoProcessor,AdapterRAM,PNPDeviceID,VideoMemoryType,Status | ConvertTo-Json")
	if err != nil {
		return gpus
	}

	output = strings.TrimSpace(output)
	var arr []map[string]any
	var obj map[string]any
	if json.Unmarshal([]byte(output), &arr) != nil {
		if json.Unmarshal([]byte(output), &obj) == nil {
			arr = []map[string]any{obj}
		}
	}

	for _, item := range arr {
		g := shared.GPU{
			Name:          "Unknown",
			Manufacturer:  "Unknown",
			Architecture:  "Unknown",
			Chipset:       "Unknown",
			DedicatedVRAM: "Unknown",
			SharedVRAM:    "Unknown",
			DriverVersion: "Unknown",
			DriverDate:    "Unknown",
			HardwareID:    "Unknown",
			CurrentStatus: "Unknown",
		}
		if v, ok := item["Name"].(string); ok {
			g.Name = v
		}
		if v, ok := item["AdapterCompatibility"].(string); ok {
			g.Manufacturer = v
		}
		if v, ok := item["VideoProcessor"].(string); ok {
			g.Chipset = v
		}
		if v, ok := item["DriverVersion"].(string); ok {
			g.DriverVersion = v
		}
		if v, ok := item["DriverDate"].(string); ok {
			g.DriverDate = v
		}
		if v, ok := item["PNPDeviceID"].(string); ok {
			g.HardwareID = v
		}
		if v, ok := item["Status"].(string); ok && v != "" {
			g.CurrentStatus = v
		}

		var vmt int
		if v, ok := item["VideoMemoryType"].(float64); ok {
			vmt = int(v)
		}
		g.Architecture = windowsGPUArchitecture(vmt, g.Manufacturer)

		if v, ok := item["AdapterRAM"].(float64); ok && v > 0 {
			vramStr := formatVRAMBytes(int64(v))
			if g.Architecture == "Integrated" {
				g.SharedVRAM = vramStr
			} else {
				g.DedicatedVRAM = vramStr
			}
		} else if g.Architecture == "Integrated" {
			g.SharedVRAM = "Shared (dynamic)"
		}

		if g.Name != "Unknown" {
			gpus = append(gpus, g)
		}
	}
	return gpus
}
