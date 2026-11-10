// Package userhomes lists the home directories of the machine's real users.
//
// The agent runs as a system service (LocalSystem on Windows, root on macOS
// and Linux), whose own home directory holds none of the users' data.
// Collectors that read per-user files (browser extensions, software, package
// inventories) iterate Dirs instead, so a service-context scan sees every
// user's data.
package userhomes

// Dirs returns the home directories of every real user on the machine, plus
// the service account's own home, without duplicates.
func Dirs() []string { return platformUserHomeDirs() }

// dedupeHomes appends home to homes/seen when non-empty and not already present.
func dedupeHomes(homes []string, seen map[string]bool, home string) []string {
	if home == "" || seen[home] {
		return homes
	}
	seen[home] = true
	return append(homes, home)
}
