package software

// userHomeDirs returns the home directories of every real user on the machine.
//
// The agent runs as a system service (LocalSystem on Windows, root on macOS and
// Linux), whose own home directory contains no browser profiles and whose
// registry hive holds no per-user software. Collecting only the service
// account's home therefore misses everything installed per-user. The collectors
// iterate this list instead so a service-context scan sees all users' data.
//
// It is a package var so tests can substitute a deterministic single-home list.
var userHomeDirs = func() []string { return platformUserHomeDirs() }

// dedupeHomes appends home to homes/seen when non-empty and not already present.
func dedupeHomes(homes []string, seen map[string]bool, home string) []string {
	if home == "" || seen[home] {
		return homes
	}
	seen[home] = true
	return append(homes, home)
}
