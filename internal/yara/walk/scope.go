// Package walk turns a threat hunting scan's scope (a preset or a path list)
// into the files a scan reads, without hurting the user's machine (#413):
// it never follows links, skips excluded folders, network and removable
// drives, oversized and cloud-only files, and files unchanged since the last
// scan with the same rules, and it applies the bundle's CPU, battery, time
// and file-count limits.
//
// It only lists files and opens them; it never reads them. Reading happens
// in the sandboxed scan workers (#412).
package walk

import (
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"sentinelgo/internal/yara"
)

// Env is what scope expansion needs from the device; tests replace it.
type Env struct {
	GOOS string
	// Homes are the users' home directories (userhomes.Dirs).
	Homes []string
	// Getenv looks up environment variables.
	Getenv func(string) string
	// ReadDir lists a directory, for "*" segments.
	ReadDir func(string) ([]os.DirEntry, error)
	// FixedDrives lists Windows' fixed local drive roots (`C:\`), for a full
	// scan.
	FixedDrives func() []string
	// Exists reports whether a path exists.
	Exists func(string) bool
}

// Roots returns the folders a scan walks. paths are the bundle's (or the
// task's) paths for this OS: when there are any they are the scope, for any
// preset; when there are none a custom scan scans nothing on this OS and
// quick and full use their defaults. Environment variables and "*" (one
// path segment) are expanded; roots that don't exist are dropped, and a
// root inside another is merged into it.
func Roots(preset string, paths []string, env Env) []string {
	if len(paths) == 0 {
		switch preset {
		case yara.PresetQuick:
			paths = quickPaths(env)
		case yara.PresetFull:
			paths = fullPaths(env)
		default:
			return nil
		}
	}
	var out []string
	for _, p := range paths {
		for _, e := range Expand(p, env) {
			if env.Exists(e) {
				out = append(out, e)
			}
		}
	}
	return dedupeNested(out, env.GOOS)
}

// quickPaths are the places malware usually lands or persists (#413's
// table), for every user profile.
func quickPaths(env Env) []string {
	var out []string
	in := func(home, rel string) string { return clean(home+separator(env.GOOS)+rel, env.GOOS) }
	switch env.GOOS {
	case "windows":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, "Desktop"),
				in(h, `AppData\Local\Temp`),
				in(h, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
		}
		out = append(out, `%PUBLIC%`, `%ProgramData%`, `%SystemRoot%\Temp`)
	case "darwin":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, "Desktop"),
				in(h, "Library/LaunchAgents"))
		}
		out = append(out, "/private/tmp", "/private/var/folders",
			"/Library/LaunchAgents", "/Library/LaunchDaemons")
	case "linux":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, ".config/autostart"))
		}
		out = append(out, "/tmp", "/var/tmp", "/dev/shm", "/etc/systemd/system", "/etc/cron*", "/root")
	}
	return out
}

// fullPaths: every fixed local drive on Windows; the data volume on macOS
// (the system volume is sealed and read-only); "/" on Linux.
func fullPaths(env Env) []string {
	switch env.GOOS {
	case "windows":
		if env.FixedDrives != nil {
			return env.FixedDrives()
		}
	case "darwin":
		return []string{darwinDataVolume}
	case "linux":
		return []string{"/"}
	}
	return nil
}

var (
	winEnvRE  = regexp.MustCompile(`%([A-Za-z0-9_()]+)%`)
	unixEnvRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// Expand expands environment variables (%VAR% on Windows, $VAR and ${VAR}
// elsewhere) and "*" segments, and cleans the result. A leading "~" means
// every user's home. A path with an unset variable, or that isn't absolute
// once expanded, expands to nothing: a scan must never fall back to the
// service's working directory.
func Expand(p string, env Env) []string {
	unset := false
	lookup := func(name string) string {
		v := env.Getenv(name)
		if v == "" {
			unset = true
		}
		return v
	}
	if env.GOOS == "windows" {
		p = winEnvRE.ReplaceAllStringFunc(p, func(m string) string { return lookup(m[1 : len(m)-1]) })
	} else {
		p = unixEnvRE.ReplaceAllStringFunc(p, func(m string) string {
			return lookup(strings.Trim(m, "${}"))
		})
	}
	if unset || p == "" {
		return nil
	}
	starts := []string{p}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		starts = nil
		for _, h := range env.Homes {
			starts = append(starts, h+p[1:])
		}
	}
	var out []string
	for _, s := range starts {
		s = clean(s, env.GOOS)
		if !isAbs(s, env.GOOS) {
			continue
		}
		out = append(out, expandStars(s, env)...)
	}
	return out
}

// expandStars expands each "*"-containing segment against the directory
// listing. Only "*" is a wildcard; other glob characters are literal.
func expandStars(p string, env Env) []string {
	sep := separator(env.GOOS)
	if !strings.Contains(p, "*") {
		return []string{p}
	}
	vol, rest := splitVolume(p, env.GOOS)
	segs := strings.Split(strings.Trim(rest, sep), sep)
	bases := []string{vol + sep}
	for _, seg := range segs {
		if seg == "" {
			continue
		}
		var next []string
		for _, b := range bases {
			if !strings.Contains(seg, "*") {
				next = append(next, join(b, seg, sep))
				continue
			}
			entries, err := env.ReadDir(b)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if starMatch(seg, e.Name(), env.GOOS == "windows") {
					next = append(next, join(b, e.Name(), sep))
				}
			}
		}
		bases = next
	}
	sort.Strings(bases)
	return bases
}

// starMatch matches name against pattern, where only "*" is special.
func starMatch(pattern, name string, fold bool) bool {
	if fold {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	last := len(parts) - 1
	for _, mid := range parts[1:last] {
		i := strings.Index(name, mid)
		if i < 0 {
			return false
		}
		name = name[i+len(mid):]
	}
	return strings.HasSuffix(name, parts[last]) && len(name) >= len(parts[last])
}

// dedupeNested drops duplicates and roots inside another root, keeping the
// order of the rest.
func dedupeNested(roots []string, goos string) []string {
	var uniq []string
	for _, r := range roots {
		dup := false
		for _, u := range uniq {
			if within(r, u, goos) && within(u, r, goos) {
				dup = true
				break
			}
		}
		if !dup {
			uniq = append(uniq, r)
		}
	}
	var out []string
	for i, r := range uniq {
		inside := false
		for j, o := range uniq {
			if i != j && within(r, o, goos) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, r)
		}
	}
	return out
}

// within reports whether p is dir or inside it. Windows paths compare
// case-insensitively.
func within(p, dir, goos string) bool {
	if goos == "windows" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	if p == dir {
		return true
	}
	sep := separator(goos)
	if !strings.HasSuffix(dir, sep) {
		dir += sep
	}
	return strings.HasPrefix(p, dir)
}

func separator(goos string) string {
	if goos == "windows" {
		return `\`
	}
	return "/"
}

// clean cleans p with goos's separator rules, whatever OS runs the code
// (so tests can check every platform's scopes).
func clean(p, goos string) string {
	if goos != "windows" {
		return cleanSlash(p)
	}
	p = strings.ReplaceAll(p, "/", `\`)
	vol, rest := splitVolume(p, goos)
	c := cleanSlash(strings.ReplaceAll(rest, `\`, "/"))
	return vol + strings.ReplaceAll(c, "/", `\`)
}

func cleanSlash(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

// splitVolume splits `C:\x` into `C:` and `\x`, and `\\host\share\x` into
// `\\host\share` and `\x`.
func splitVolume(p, goos string) (string, string) {
	if goos != "windows" {
		return "", p
	}
	if len(p) >= 2 && p[1] == ':' {
		return strings.ToUpper(p[:1]) + ":", p[2:]
	}
	if strings.HasPrefix(p, `\\`) {
		parts := strings.SplitN(p[2:], `\`, 3)
		if len(parts) >= 2 {
			vol := `\\` + parts[0] + `\` + parts[1]
			if len(parts) == 3 {
				return vol, `\` + parts[2]
			}
			return vol, `\`
		}
	}
	return "", p
}

func isAbs(p, goos string) bool {
	if goos != "windows" {
		return strings.HasPrefix(p, "/")
	}
	vol, rest := splitVolume(p, goos)
	return vol != "" && strings.HasPrefix(rest, `\`)
}

func join(base, name, sep string) string {
	if strings.HasSuffix(base, sep) {
		return base + name
	}
	return base + sep + name
}
