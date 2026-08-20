package osdetail

import (
	"strconv"
	"strings"
)

// activationStatusName maps a Win32_SoftwareLicensingProduct.LicenseStatus
// value to a stable, human-readable name. Values per Microsoft's documented
// SL_GENUINE_STATE / LicenseStatus enum.
//
// No build tag: pure mapping, unit tested on every host regardless of GOOS.
func activationStatusName(status uint32) string {
	switch status {
	case 0:
		return "unlicensed"
	case 1:
		return "licensed"
	case 2:
		return "out_of_box_grace"
	case 3:
		return "out_of_tolerance_grace"
	case 4:
		return "non_genuine_grace"
	case 5:
		return "notification"
	case 6:
		return "extended_grace"
	default:
		return "unknown"
	}
}

// earliestUnixTime scans newline-separated integer Unix timestamps (as
// printed by `rpm -qa --qf '%{installtime}\n'`) and returns the smallest one.
// Unparseable lines are skipped rather than failing the whole scan — one
// malformed rpm entry must not lose every other package's install time.
func earliestUnixTime(output string) (int64, bool) {
	var earliest int64
	found := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			continue
		}
		if !found || v < earliest {
			earliest = v
			found = true
		}
	}
	return earliest, found
}
