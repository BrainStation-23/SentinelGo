package software

import (
	"os"
	"path/filepath"
)

// platformUserHomeDirs returns /root, every directory under /home, and the
// service account's own home. Running as root, the agent can read them all.
func platformUserHomeDirs() []string {
	seen := make(map[string]bool)
	var homes []string

	if h, err := os.UserHomeDir(); err == nil {
		homes = dedupeHomes(homes, seen, h)
	}
	homes = dedupeHomes(homes, seen, "/root")

	entries, err := os.ReadDir("/home")
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		homes = dedupeHomes(homes, seen, filepath.Join("/home", e.Name()))
	}
	return homes
}
