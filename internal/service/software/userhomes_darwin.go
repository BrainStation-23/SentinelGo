package software

import (
	"os"
	"path/filepath"
)

// nonUserHomes are entries under /Users that are not real interactive users.
var nonUserHomes = map[string]bool{
	"Shared":     true,
	".localized": true,
	"Guest":      true,
}

// platformUserHomeDirs returns every real user home under /Users, plus the
// service account's own home. Running as root, the agent can read them all.
func platformUserHomeDirs() []string {
	seen := make(map[string]bool)
	var homes []string

	if h, err := os.UserHomeDir(); err == nil {
		homes = dedupeHomes(homes, seen, h)
	}

	entries, err := os.ReadDir("/Users")
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() || nonUserHomes[e.Name()] {
			continue
		}
		homes = dedupeHomes(homes, seen, filepath.Join("/Users", e.Name()))
	}
	return homes
}
