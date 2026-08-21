package secureboot

import (
	"fmt"
	"strings"
)

// parseRegDWORD extracts the integer value of a REG_DWORD from `reg query`
// output. It returns an error rather than a sentinel so a missing value cannot
// be mistaken for "disabled" — the gap between "no UEFI here" and "Secure Boot
// is off" is the gap between silence and a security alert.
//
// Expected line shape: "    UEFISecureBootEnabled    REG_DWORD    0x1"
func parseRegDWORD(output, valueName string) (int, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), strings.ToLower(valueName)) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if !strings.EqualFold(f, "REG_DWORD") || i+1 >= len(fields) {
				continue
			}
			var n int
			if _, err := fmt.Sscanf(fields[i+1], "0x%x", &n); err == nil {
				return n, nil
			}
			if _, err := fmt.Sscanf(fields[i+1], "%d", &n); err == nil {
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("value %q not found", valueName)
}

// stateFromDWORD maps the UEFISecureBootEnabled DWORD to a section state.
func stateFromDWORD(v int) string {
	switch v {
	case 1:
		return StateEnabled
	case 0:
		return StateDisabled
	default:
		return StateUnknown
	}
}

// parseMokutil reads `mokutil --sb-state` output.
func parseMokutil(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "secureboot enabled"):
		return StateEnabled
	case strings.Contains(lower, "secureboot disabled"):
		return StateDisabled
	default:
		return StateUnknown
	}
}

// parseEFIVar reads the raw SecureBoot EFI variable: a 4-byte attribute header
// followed by one value byte (1 = enabled, 0 = disabled).
func parseEFIVar(data []byte) string {
	if len(data) < 5 {
		return StateUnknown
	}
	if data[4] == 1 {
		return StateEnabled
	}
	return StateDisabled
}

// parseBridgeOSSecurity reads `system_profiler SPiBridgeDataType` output.
//
// "No Security" is Apple's own wording for a fully permissive boot policy;
// "Full Security" and "Reduced Security" both still verify the boot chain, so
// both count as enabled. A bridge that reports neither is left unknown rather
// than assumed either way.
func parseBridgeOSSecurity(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "no security"):
		return StateDisabled
	case strings.Contains(lower, "full security"), strings.Contains(lower, "reduced security"):
		return StateEnabled
	default:
		return StateUnknown
	}
}
