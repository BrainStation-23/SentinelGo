package identity

import "strings"

// parsePlatformUUID extracts the IOPlatformUUID value from ioreg's
// `"IOPlatformUUID" = "value"` line format.
//
// This has no build tag, unlike its caller in identity_darwin.go, so the
// string-handling logic is unit tested on every platform CI runs on rather
// than only on a macOS host — the same split used throughout
// internal/osinfo/system/parse.go.
func parsePlatformUUID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.Split(line, `"`)
		for i, part := range parts {
			if part == "IOPlatformUUID" && i+2 < len(parts) {
				return parts[i+2]
			}
		}
	}
	return ""
}
