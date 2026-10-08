//go:build darwin || windows

package network

import (
	"math"
	"strconv"
	"strings"
)

// Shared by the macOS (networksetup) and Windows (netsh) speed parsers; Linux
// reads the speed from sysfs as a plain integer, so this file is not built there.

// linkSpeedMbps converts a link speed such as "1000 Mbps" or "10 Gbps"
// (value and unit already split) to Mbps. ok is false for non-numeric or
// negative values and for Gbps values whose conversion would overflow int64.
func linkSpeedMbps(value, unit string) (mbps int64, ok bool) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	if strings.HasPrefix(strings.ToLower(unit), "g") {
		const mbpsPerGbps = 1000
		if n > math.MaxInt64/mbpsPerGbps {
			return 0, false
		}
		return n * mbpsPerGbps, true
	}
	return n, true
}
