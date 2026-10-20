//go:build linux || windows

package software

// qualifyMultiArch appends ":<arch>" to the names of packages installed for
// more than one architecture (e.g. libc6 for amd64 and i386, glibc for x86_64
// and i686, or a Windows program installed as both x86 and x64), whose names
// would otherwise collide in the catalog, which is keyed by name and source.
// rawArchs holds each package's architecture as the package manager printed it.
// Names installed once are left as they are.
func qualifyMultiArch(packages []SoftwareInfo, rawArchs []string) {
	archs := make(map[string]map[string]bool, len(packages))
	for i, p := range packages {
		if archs[p.Name] == nil {
			archs[p.Name] = map[string]bool{}
		}
		archs[p.Name][rawArchs[i]] = true
	}
	for i := range packages {
		if len(archs[packages[i].Name]) > 1 && rawArchs[i] != "" {
			packages[i].Name += ":" + rawArchs[i]
		}
	}
}
