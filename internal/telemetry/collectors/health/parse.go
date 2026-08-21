package health

import "strconv"
import "strings"

// This file holds every platform's pure parsing/conversion logic with no
// build tag, so it is unit tested on every host regardless of GOOS.

// ── Linux: sysfs battery units ──────────────────────────────────────────────

// microAhToMWh converts a µAh capacity at a given µV to milliwatt-hours:
// mWh = (µAh × µV) / 1e9. This is the matrix-documented conversion needed
// when a battery exposes charge_* (µAh) rather than energy_* (µWh) —
// "the classic bug" is applying it to the wrong unit or skipping it.
func microAhToMWh(microAh, microV int64) uint64 {
	return uint64(microAh) * uint64(microV) / 1_000_000_000
}

// ── macOS: ioreg AppleSmartBattery ──────────────────────────────────────────

// mAhToMWh converts a mAh capacity at a given mV to milliwatt-hours:
// mWh = (mAh × mV) / 1000.
func mAhToMWh(mAh, mV int64) uint64 {
	return uint64(mAh) * uint64(mV) / 1000
}

// parseIoregFields parses `ioreg -rc`'s `"Key" = Value` lines into a map.
func parseIoregFields(output string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(line[:idx]), `"`)
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			fields[key] = val
		}
	}
	return fields
}

func parseIoregInt(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
