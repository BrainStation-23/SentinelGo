package walk

import "strings"

// alwaysExcluded are never scanned (#413): the agent's own install and data
// folders, other security products' quarantine and definition folders, the
// kernel's pseudo file systems and the swap and hibernation files.
// Environment variables are expanded like scope paths.
func alwaysExcluded(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			`C:\sentinelgo`,
			`%ProgramData%\Microsoft\Windows Defender`,
			`%ProgramData%\Microsoft\Windows Defender Advanced Threat Protection`,
		}
	case "darwin":
		return []string{
			"/opt/sentinelgo",
			"/dev",
			"/private/var/vm",
			"/System/Volumes/VM",
			"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
			"/System/Library/CoreServices/XProtect.bundle",
		}
	case "linux":
		return []string{
			"/opt/sentinelgo",
			"/proc",
			"/sys",
			"/dev", // /dev/shm is let through (see Excluder.Excluded)
			"/run/user/*/gvfs",
			"/var/lib/clamav",
			"/swapfile",
			"/swap.img",
		}
	}
	return nil
}

// excludedNames are skipped wherever they are, by file or folder name.
var excludedNames = map[string][]string{
	"windows": {"system volume information", "pagefile.sys", "hiberfil.sys", "swapfile.sys"},
}

// Excluder decides which paths a scan skips.
type Excluder struct {
	goos  string
	paths []string
	names map[string]bool
}

// NewExcluder combines the always-excluded paths, the running binary's
// folder (extra, may be empty) and the bundle's exclusions for this OS.
func NewExcluder(bundle []string, extra string, env Env) *Excluder {
	x := &Excluder{goos: env.GOOS, names: map[string]bool{}}
	for _, p := range append(alwaysExcluded(env.GOOS), bundle...) {
		x.paths = append(x.paths, Expand(p, env)...)
	}
	if extra != "" {
		x.paths = append(x.paths, clean(extra, env.GOOS))
	}
	for _, n := range excludedNames[env.GOOS] {
		x.names[n] = true
	}
	return x
}

// Excluded reports whether path (a folder or file named name) is skipped.
func (x *Excluder) Excluded(path, name string) bool {
	if x == nil {
		return false
	}
	if len(x.names) > 0 && x.names[strings.ToLower(name)] {
		return true
	}
	alt, hasAlt := firmlinked(path, x.goos)
	for _, p := range x.paths {
		if !within(path, p, x.goos) && (!hasAlt || !within(alt, p, x.goos)) {
			continue
		}
		if x.goos == "linux" && p == "/dev" &&
			(path == "/dev" || within(path, "/dev/shm", x.goos)) {
			// Device nodes are skipped, but /dev/shm is where payloads
			// are dropped, and a full scan of / must reach it.
			continue
		}
		return true
	}
	return false
}

// darwinDataVolume is where a macOS full scan starts: the writable data
// volume, which the system volume shows through firmlinks (/Users,
// /Library, /opt, /private and others).
const darwinDataVolume = "/System/Volumes/Data"

// firmlinked returns the path a macOS data-volume path is known by
// (/System/Volumes/Data/Users/a -> /Users/a), so exclusions and mounts
// written the usual way still match during a full scan.
func firmlinked(path, goos string) (string, bool) {
	if goos != "darwin" || !strings.HasPrefix(path, darwinDataVolume+"/") {
		return "", false
	}
	return path[len(darwinDataVolume):], true
}
