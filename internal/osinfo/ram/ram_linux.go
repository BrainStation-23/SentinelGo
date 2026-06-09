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

// parseDmidecodeOutput parses the output of "dmidecode -t memory" into RAM sticks.
// It is exported for testing.
func parseDmidecodeOutput(output string) ([]shared.RAMStick, uint64) {
	var rams []shared.RAMStick
	var totalBytes uint64

	lines := strings.Split(output, "\n")
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

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Memory Device") {
			flush()
			current = &shared.RAMStick{}
		} else if current != nil {
			switch {
			case strings.HasPrefix(line, "Size:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentSizeBytes = parseMemorySize(strings.TrimSpace(parts[1]))
				}
			case strings.HasPrefix(line, "Manufacturer:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := normalizeRAMManufacturer(strings.TrimSpace(parts[1]))
					current.Manufacturer = v
				}
			case strings.HasPrefix(line, "Part Number:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if !isMeaningless(v) {
						current.Name = v
					}
				}
			case strings.HasPrefix(line, "Type:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if !isMeaningless(v) {
						current.ArchitectureType = v
					}
				}
			case strings.HasPrefix(line, "Speed:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					var speed int
					_, _ = fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &speed)
					current.ClockSpeedMHz = speed
				}
			case strings.HasPrefix(line, "Serial Number:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if !isMeaningless(v) {
						current.Serial = v
					}
				}
			case strings.HasPrefix(line, "Form Factor:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if !isMeaningless(v) {
						current.FormFactor = v
					}
				}
			case strings.HasPrefix(line, "Locator:") && !strings.HasPrefix(line, "Bank Locator:"):
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if !isMeaningless(v) {
						current.Slot = v
					}
				}
			}
		}
	}
	flush()

	return rams, totalBytes
}

// fallbackFromProcMeminfo is used when dmidecode is unavailable or returns no sticks.
// It reads /proc/meminfo for total size and probes EDAC/lshw/DMI for type metadata.
func fallbackFromProcMeminfo() ([]shared.RAMStick, uint64) {
	var totalMemKB uint64
	if meminfo, err := shared.ReadFileContent("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(meminfo, "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						totalMemKB = kb
					}
				}
				break
			}
		}
	}
	if totalMemKB == 0 {
		return nil, 0
	}

	var ramType, manufacturer string
	var clockSpeed int

	// EDAC subsystem exposes per-DIMM memory type when available
	if dimmType, err := shared.ReadFileContent("/sys/devices/system/edac/mc/mc0/dimm0/dimm_mem_type"); err == nil {
		ramType = strings.TrimSpace(dimmType)
	}
	if ramType == "" {
		if mcType, err := shared.ReadFileContent("/sys/devices/system/edac/mc/mc0/mc_type"); err == nil {
			ramType = strings.TrimSpace(mcType)
		}
	}

	if ramType == "" || clockSpeed == 0 || manufacturer == "" {
		if lshwOut, err := shared.RunCommand("lshw", "-C", "memory"); err == nil {
			if ramType == "" {
				upper := strings.ToUpper(lshwOut)
				switch {
				case strings.Contains(upper, "LPDDR5"):
					ramType = "LPDDR5"
				case strings.Contains(upper, "LPDDR4"):
					ramType = "LPDDR4"
				case strings.Contains(upper, "DDR5"):
					ramType = "DDR5"
				case strings.Contains(upper, "DDR4"):
					ramType = "DDR4"
				case strings.Contains(upper, "DDR3"):
					ramType = "DDR3"
				case strings.Contains(upper, "DDR2"):
					ramType = "DDR2"
				}
			}
			if manufacturer == "" {
				for _, line := range strings.Split(lshwOut, "\n") {
					if strings.Contains(line, "vendor:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) >= 2 {
							vendor := strings.TrimSpace(parts[1])
							if vendor != "" && vendor != "0x" && vendor != "0x0000" {
								manufacturer = vendor
								break
							}
						}
					}
				}
			}
			// lshw reports memory bus speed as "clock:NNNNMHz"
			if clockSpeed == 0 {
				for _, line := range strings.Split(lshwOut, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "clock:") {
						var speed int
						if _, err := fmt.Sscanf(trimmed, "clock:%dMHz", &speed); err == nil && speed > 0 {
							clockSpeed = speed
							break
						}
					}
				}
			}
		}
	}

	// Board vendor is the best approximation available without per-DIMM data
	if manufacturer == "" {
		if boardVendor, err := shared.ReadFileContent("/sys/class/dmi/id/board_vendor"); err == nil {
			manufacturer = strings.TrimSpace(boardVendor)
		}
	}
	if manufacturer == "" {
		if sysVendor, err := shared.ReadFileContent("/sys/class/dmi/id/sys_vendor"); err == nil {
			manufacturer = strings.TrimSpace(sysVendor)
		}
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
