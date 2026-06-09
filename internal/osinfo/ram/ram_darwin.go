package ram

import (
	"encoding/json"
	"fmt"

	"sentinelgo/internal/osinfo/shared"
)

func getRAMs() shared.RAMInfo {
	var rams []shared.RAMStick
	var totalBytes uint64

	output, err := shared.RunCommand("system_profiler", "SPMemoryDataType", "-json")
	if err != nil {
		return shared.RAMInfo{}
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return shared.RAMInfo{}
	}

	memData, ok := result["SPMemoryDataType"].([]any)
	if !ok {
		return shared.RAMInfo{}
	}

	for _, memItem := range memData {
		memMap, ok := memItem.(map[string]any)
		if !ok {
			continue
		}
		if items, ok := memMap["_items"].([]any); ok {
			// Intel Macs: individual DIMM slots under _items
			for _, item := range items {
				itemMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				ram := shared.RAMStick{}
				var sizeBytes uint64
				if v, ok := itemMap["_name"].(string); ok {
					ram.Name = v
					ram.Slot = v // physical slot identifier, e.g. "DIMM0"
				}
				if v, ok := itemMap["dimm_vendor"].(string); ok {
					ram.Manufacturer = v
				}
				if v, ok := itemMap["dimm_size"].(string); ok {
					sizeBytes = parseMemorySize(v)
					ram.Capacity = sizeBytes
					totalBytes += sizeBytes
				}
				if v, ok := itemMap["dimm_type"].(string); ok {
					ram.ArchitectureType = v
				}
				if v, ok := itemMap["dimm_speed"].(string); ok {
					var speed int
					_, _ = fmt.Sscanf(v, "%d", &speed)
					ram.ClockSpeedMHz = speed
				}
				if sizeBytes > 0 {
					rams = append(rams, ram)
				}
			}
		} else {
			// Apple Silicon: unified memory reported at top level.
			// The size is keyed as "SPMemoryDataType" (same name as the outer array),
			// not "dimm_size" which is used on Intel Macs.
			ram := shared.RAMStick{}
			ram.FormFactor = "Unified"
			var sizeBytes uint64
			if v, ok := memMap["_name"].(string); ok {
				ram.Name = v
			} else {
				ram.Name = "Unified Memory"
			}
			if v, ok := memMap["dimm_manufacturer"].(string); ok {
				ram.Manufacturer = v
			}
			if v, ok := memMap["dimm_size"].(string); ok {
				sizeBytes = parseMemorySize(v)
			} else if v, ok := memMap["SPMemoryDataType"].(string); ok {
				sizeBytes = parseMemorySize(v)
			}
			ram.Capacity = sizeBytes
			totalBytes += sizeBytes
			if v, ok := memMap["dimm_type"].(string); ok {
				ram.ArchitectureType = v
			}
			if v, ok := memMap["dimm_speed"].(string); ok {
				var speed int
				_, _ = fmt.Sscanf(v, "%d", &speed)
				ram.ClockSpeedMHz = speed
			}
			if sizeBytes > 0 {
				rams = append(rams, ram)
			}
		}
	}

	// sysctl fallback: if system_profiler returned no size info, derive total from the kernel.
	if totalBytes == 0 {
		if out, err := shared.RunCommand("sysctl", "-n", "hw.memsize"); err == nil {
			var n uint64
			if _, err := fmt.Sscanf(out, "%d", &n); err == nil {
				totalBytes = n
			}
		}
	}

	return shared.RAMInfo{
		TotalCapacity: totalBytes,
		RAMs:          rams,
	}
}
