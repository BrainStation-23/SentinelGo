package selfdefense

import (
	"os"
	"path/filepath"
	"strings"
)

// dedupeExisting returns the paths that exist on disk, with duplicates removed.
//
// Duplicates are real: on Unix the install directory and the config directory
// are nested, and filepath.Dir(configPath) is usually DataDir already. Auditing
// the same path twice would report the same problem twice in the reason string,
// which reads like two separate findings.
//
// Comparison is case-insensitive because the Windows paths this guards are.
func dedupeExisting(candidates []string) []string {
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		clean := filepath.Clean(candidate)
		key := strings.ToLower(clean)
		if _, dup := seen[key]; dup {
			continue
		}
		if _, err := os.Lstat(clean); err != nil {
			// Not yet created (the staging directory before the first update),
			// so there is nothing to audit and nothing to be wrong.
			continue
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	return out
}
