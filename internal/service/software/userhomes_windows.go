package software

import (
	"os"
	"path/filepath"
)

// nonUserProfiles are entries under C:\Users that are not real interactive users.
var nonUserProfiles = map[string]bool{
	"Public":       true,
	"Default":      true,
	"Default User": true,
	"All Users":    true,
	"defaultuser0": true,
	"WDAGUtilityAccount": true,
}

// platformUserHomeDirs returns every real user profile under %SystemDrive%\Users,
// plus the service account's own home. As the SYSTEM service the agent can read
// all profile directories.
func platformUserHomeDirs() []string {
	seen := make(map[string]bool)
	var homes []string

	if h, err := os.UserHomeDir(); err == nil {
		homes = dedupeHomes(homes, seen, h)
	}

	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	usersDir := drive + `\Users`

	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() || nonUserProfiles[e.Name()] {
			continue
		}
		homes = dedupeHomes(homes, seen, filepath.Join(usersDir, e.Name()))
	}
	return homes
}
