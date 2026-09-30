package ram

import (
	"encoding/json"
	"fmt"

	"sentinelgo/internal/osinfo/shared"
)

func getRAMs() shared.RAMInfo {
	output, err := shared.RunCommand("system_profiler", "SPMemoryDataType", "-json")
	if err != nil {
		return shared.RAMInfo{}
	}

	memData, ok := parseDarwinMemoryData(output)
	if !ok {
		return shared.RAMInfo{}
	}

	rams, totalBytes := parseMemoryProfilerData(memData)

	// sysctl fallback: if system_profiler returned no size info, derive total from the kernel.
	if totalBytes == 0 {
		totalBytes = totalMemoryFromSysctl()
	}

	return shared.RAMInfo{
		TotalCapacity: totalBytes,
		RAMs:          rams,
	}
}

// parseDarwinMemoryData unmarshals system_profiler's SPMemoryDataType JSON
// output and returns the top-level memory data array.
func parseDarwinMemoryData(output string) ([]any, bool) {
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, false
	}
	memData, ok := result["SPMemoryDataType"].([]any)
	return memData, ok
}

// parseMemoryProfilerData walks each entry of SPMemoryDataType, dispatching to
// the Intel (per-DIMM "_items") or Apple Silicon (unified memory) parser as
// appropriate.
func parseMemoryProfilerData(memData []any) ([]shared.RAMStick, uint64) {
	var rams []shared.RAMStick
	var totalBytes uint64

	for _, memItem := range memData {
		memMap, ok := memItem.(map[string]any)
		if !ok {
			continue
		}
		if items, ok := memMap["_items"].([]any); ok {
			// Intel Macs: individual DIMM slots under _items
			groupRAMs, groupBytes := parseIntelMemoryGroup(items)
			rams = append(rams, groupRAMs...)
			totalBytes += groupBytes
			continue
		}
		// Apple Silicon: unified memory reported at top level.
		if ram, sizeBytes, ok := parseAppleSiliconMemory(memMap); ok {
			rams = append(rams, ram)
			totalBytes += sizeBytes
		}
	}

	return rams, totalBytes
}

// parseIntelMemoryGroup parses the "_items" array of individual DIMM slots
// reported on Intel Macs.
func parseIntelMemoryGroup(items []any) ([]shared.RAMStick, uint64) {
	var rams []shared.RAMStick
	var totalBytes uint64
	for _, item := range items {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if ram, sizeBytes, ok := parseIntelDIMM(itemMap); ok {
			rams = append(rams, ram)
			totalBytes += sizeBytes
		}
	}
	return rams, totalBytes
}

// parseIntelDIMM parses a single DIMM slot entry from Intel Mac
// system_profiler output. ok is false when the slot reports no size
// (e.g. an empty slot).
func parseIntelDIMM(itemMap map[string]any) (shared.RAMStick, uint64, bool) {
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
	}
	if v, ok := itemMap["dimm_type"].(string); ok {
		ram.ArchitectureType = v
	}
	if v, ok := itemMap["dimm_speed"].(string); ok {
		var speed int
		_, _ = fmt.Sscanf(v, "%d", &speed)
		ram.ClockSpeedMHz = speed
	}
	return ram, sizeBytes, sizeBytes > 0
}

// parseAppleSiliconMemory parses the top-level unified-memory entry reported
// on Apple Silicon Macs. The size is keyed as "SPMemoryDataType" (same name
// as the outer array), not "dimm_size" which is used on Intel Macs.
func parseAppleSiliconMemory(memMap map[string]any) (shared.RAMStick, uint64, bool) {
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
	if v, ok := memMap["dimm_type"].(string); ok {
		ram.ArchitectureType = v
	}
	if v, ok := memMap["dimm_speed"].(string); ok {
		var speed int
		_, _ = fmt.Sscanf(v, "%d", &speed)
		ram.ClockSpeedMHz = speed
	}
	return ram, sizeBytes, sizeBytes > 0
}

// totalMemoryFromSysctl derives total physical memory from the kernel via
// sysctl, used when system_profiler's JSON output carries no usable size
// fields.
func totalMemoryFromSysctl() uint64 {
	out, err := shared.RunCommand("sysctl", "-n", "hw.memsize")
	if err != nil {
		return 0
	}
	var n uint64
	if _, err := fmt.Sscanf(out, "%d", &n); err != nil {
		return 0
	}
	return n
}
