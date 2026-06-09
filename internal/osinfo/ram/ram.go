package ram

import (
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Get returns RAM information for the current platform.
func Get() shared.RAMInfo {
	return getRAMs()
}

// normalizeRAMManufacturer normalises both plain-English names and garbled values
// returned by firmware. Meaningless sentinels are collapsed to ""; recognised
// vendor substrings are mapped to their canonical trade names; everything else
// is returned unchanged so unknown real brands are not silently dropped.
func normalizeRAMManufacturer(raw string) string {
	trimmed := strings.TrimSpace(raw)
	switch strings.ToLower(trimmed) {
	case "", "unknown", "not provided", "not specified", "not applicable":
		return ""
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lower, "samsung"):
		return "Samsung"
	case strings.Contains(lower, "hynix"):
		return "SK Hynix"
	case strings.Contains(lower, "micron"):
		return "Micron"
	case strings.Contains(lower, "kingston"):
		return "Kingston"
	case strings.Contains(lower, "corsair"):
		return "Corsair"
	case strings.Contains(lower, "crucial"):
		return "Crucial"
	case strings.Contains(lower, "g.skill") || strings.Contains(lower, "gskill"):
		return "G.Skill"
	case strings.Contains(lower, "patriot"):
		return "Patriot"
	case strings.Contains(lower, "teamgroup") || strings.Contains(lower, "team group"):
		return "Team Group"
	case strings.Contains(lower, "adata") || strings.Contains(lower, "a-data"):
		return "ADATA"
	case strings.Contains(lower, "transcend"):
		return "Transcend"
	case strings.Contains(lower, "nanya"):
		return "Nanya"
	case strings.Contains(lower, "ramaxel"):
		return "Ramaxel"
	case strings.Contains(lower, "infineon"):
		return "Infineon"
	}

	return trimmed
}

// parseMemorySize parses human-readable size strings such as "8 GB", "4096 MB",
// "1 TB", "512 KB" into bytes. If no recognised unit suffix is found the number
// is treated as gigabytes (matching existing macOS behaviour). Returns 0 for
// empty, zero, or non-numeric input.
func parseMemorySize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	var value float64
	if _, err := fmt.Sscanf(s, "%f", &value); err != nil || value <= 0 {
		return 0
	}

	upper := strings.ToUpper(s)
	switch {
	case strings.Contains(upper, "TB"):
		return uint64(value * 1024 * 1024 * 1024 * 1024)
	case strings.Contains(upper, "GB"):
		return uint64(value * 1024 * 1024 * 1024)
	case strings.Contains(upper, "MB"):
		return uint64(value * 1024 * 1024)
	case strings.Contains(upper, "KB"):
		return uint64(value * 1024)
	default:
		// Default to GB (matches existing macOS parseDimmSize behaviour)
		return uint64(value * 1024 * 1024 * 1024)
	}
}
