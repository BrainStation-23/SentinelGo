package ram

import (
	"fmt"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getRAMs() shared.RAMInfo {
	output, err := shared.RunCommand("dmidecode", "-t", "memory")
	if err == nil {
		rams, totalBytes := parseDmidecodeOutput(output)
		if len(rams) > 0 {
			return shared.RAMInfo{
				TotalCapacity: totalBytes,
				RAMs:          rams,
			}
		}
	}

	rams, totalBytes := fallbackFromProcMeminfo()
	return shared.RAMInfo{
		TotalCapacity: totalBytes,
		RAMs:          rams,
	}
}

// isMeaningless reports whether s is a firmware sentinel that carries no real data.
func isMeaningless(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unknown", "not provided", "not specified", "not applicable":
		return true
	}
	return false
}

// fieldValue splits a "Key: Value" dmidecode line and returns the trimmed value.
// ok is false when the line has no colon separator.
func fieldValue(line string) (string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

// applyDmidecodeField sets the appropriate field on stick from a single dmidecode line.
func applyDmidecodeField(line string, stick *shared.RAMStick, sizeBytes *uint64) {
	switch {
	case strings.HasPrefix(line, "Size:"):
		if v, ok := fieldValue(line); ok {
			*sizeBytes = parseMemorySize(v)
		}
	case strings.HasPrefix(line, "Manufacturer:"):
		if v, ok := fieldValue(line); ok {
			stick.Manufacturer = normalizeRAMManufacturer(v)
		}
	case strings.HasPrefix(line, "Part Number:"):
		if v, ok := fieldValue(line); ok && !isMeaningless(v) {
			stick.Name = v
		}
	case strings.HasPrefix(line, "Type:"):
		if v, ok := fieldValue(line); ok && !isMeaningless(v) {
			stick.ArchitectureType = v
		}
	case strings.HasPrefix(line, "Speed:"):
		if v, ok := fieldValue(line); ok {
			var speed int
			_, _ = fmt.Sscanf(v, "%d", &speed)
			stick.ClockSpeedMHz = speed
		}
	case strings.HasPrefix(line, "Serial Number:"):
		if v, ok := fieldValue(line); ok && !isMeaningless(v) {
			stick.Serial = v
		}
	case strings.HasPrefix(line, "Form Factor:"):
		if v, ok := fieldValue(line); ok && !isMeaningless(v) {
			stick.FormFactor = v
		}
	case strings.HasPrefix(line, "Locator:") && !strings.HasPrefix(line, "Bank Locator:"):
		if v, ok := fieldValue(line); ok && !isMeaningless(v) {
			stick.Slot = v
		}
	}
}

// parseDmidecodeOutput parses the output of "dmidecode -t memory" into RAM sticks.
// It is exported for testing.
func parseDmidecodeOutput(output string) ([]shared.RAMStick, uint64) {
	var rams []shared.RAMStick
	var totalBytes uint64
	var current *shared.RAMStick
	var currentSizeBytes uint64

	flush := func() {
		if current != nil && currentSizeBytes > 0 {
			current.Capacity = currentSizeBytes
			totalBytes += currentSizeBytes
			rams = append(rams, *current)
		}
		current = nil
		currentSizeBytes = 0
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Memory Device") {
			flush()
			current = &shared.RAMStick{}
		} else if current != nil {
			applyDmidecodeField(line, current, &currentSizeBytes)
		}
	}
	flush()

	return rams, totalBytes
}

// readTotalMemKB returns the MemTotal value from /proc/meminfo in kilobytes, or 0 on failure.
func readTotalMemKB() uint64 {
	meminfo, err := shared.ReadFileContent("/proc/meminfo")
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(meminfo, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					return kb
				}
			}
			break
		}
	}
	return 0
}

// ramTypeFromEDAC probes the EDAC kernel subsystem for the memory type of the first DIMM.
func ramTypeFromEDAC() string {
	if dimmType, err := shared.ReadFileContent("/sys/devices/system/edac/mc/mc0/dimm0/dimm_mem_type"); err == nil {
		if t := strings.TrimSpace(dimmType); t != "" {
			return t
		}
	}
	if mcType, err := shared.ReadFileContent("/sys/devices/system/edac/mc/mc0/mc_type"); err == nil {
		return strings.TrimSpace(mcType)
	}
	return ""
}

// lshwRAMType extracts the DDR generation string from uppercased lshw output.
func lshwRAMType(upper string) string {
	switch {
	case strings.Contains(upper, "LPDDR5"):
		return "LPDDR5"
	case strings.Contains(upper, "LPDDR4"):
		return "LPDDR4"
	case strings.Contains(upper, "DDR5"):
		return "DDR5"
	case strings.Contains(upper, "DDR4"):
		return "DDR4"
	case strings.Contains(upper, "DDR3"):
		return "DDR3"
	case strings.Contains(upper, "DDR2"):
		return "DDR2"
	}
	return ""
}

// lshwManufacturer extracts the memory vendor from lshw -C memory output.
func lshwManufacturer(lshwOut string) string {
	for line := range strings.SplitSeq(lshwOut, "\n") {
		if !strings.Contains(line, "vendor:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		vendor := strings.TrimSpace(parts[1])
		if vendor != "" && vendor != "0x" && vendor != "0x0000" {
			return vendor
		}
	}
	return ""
}

// lshwClockSpeed extracts the memory bus speed in MHz from lshw -C memory output.
func lshwClockSpeed(lshwOut string) int {
	for line := range strings.SplitSeq(lshwOut, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "clock:") {
			continue
		}
		var speed int
		if _, err := fmt.Sscanf(trimmed, "clock:%dMHz", &speed); err == nil && speed > 0 {
			return speed
		}
	}
	return 0
}

// enrichFromLshw fills any missing RAM metadata fields using lshw -C memory.
func enrichFromLshw(ramType, manufacturer string, clockSpeed int) (string, string, int) {
	lshwOut, err := shared.RunCommand("lshw", "-C", "memory")
	if err != nil {
		return ramType, manufacturer, clockSpeed
	}
	if ramType == "" {
		ramType = lshwRAMType(strings.ToUpper(lshwOut))
	}
	if manufacturer == "" {
		manufacturer = lshwManufacturer(lshwOut)
	}
	if clockSpeed == 0 {
		clockSpeed = lshwClockSpeed(lshwOut)
	}
	return ramType, manufacturer, clockSpeed
}

// manufacturerFromDMI reads the board or system vendor from DMI sysfs as a last resort.
func manufacturerFromDMI() string {
	if boardVendor, err := shared.ReadFileContent("/sys/class/dmi/id/board_vendor"); err == nil {
		if v := strings.TrimSpace(boardVendor); v != "" {
			return v
		}
	}
	if sysVendor, err := shared.ReadFileContent("/sys/class/dmi/id/sys_vendor"); err == nil {
		return strings.TrimSpace(sysVendor)
	}
	return ""
}

// fallbackFromProcMeminfo is used when dmidecode is unavailable or returns no sticks.
// It reads /proc/meminfo for total size and probes EDAC/lshw/DMI for type metadata.
func fallbackFromProcMeminfo() ([]shared.RAMStick, uint64) {
	totalMemKB := readTotalMemKB()
	if totalMemKB == 0 {
		return nil, 0
	}

	ramType := ramTypeFromEDAC()
	ramType, manufacturer, clockSpeed := enrichFromLshw(ramType, "", 0)
	if manufacturer == "" {
		manufacturer = manufacturerFromDMI()
	}

	if ramType == "" {
		ramType = "Unknown"
	}
	if manufacturer == "" {
		manufacturer = "Unknown"
	}

	totalBytes := totalMemKB * 1024
	return []shared.RAMStick{{
		Name:             "System Memory",
		Capacity:         totalBytes,
		ArchitectureType: ramType,
		Manufacturer:     manufacturer,
		ClockSpeedMHz:    clockSpeed,
	}}, totalBytes
}
