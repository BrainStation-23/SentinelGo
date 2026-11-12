package netctl

import (
	"strings"

	"sentinelgo/internal/dlp/policy"
)

// Why a blocked app isn't applied (NotApplied.Reason).
const (
	ReasonSignerOnly   = "signer_only"    // no path: WFP matches executables by path
	ReasonNotAbsolute  = "not_absolute"   // relative, wildcards, or an unknown %VAR%
	ReasonPathNotFound = "path_not_found" // not installed (looked for again on every refresh)
)

// perUserVars are expanded once for each local profile.
var perUserVars = map[string]string{
	"userprofile":  "",
	"localappdata": `AppData\Local`,
	"appdata":      `AppData\Roaming`,
}

// expandApp turns a blocked app's path into the executables to block: %VAR%
// from env (names in any case), and the per-user variables once for each
// profile directory. It returns a reason instead when the path can't be
// used.
func expandApp(a policy.App, env map[string]string, profiles []string) ([]string, string) {
	if strings.TrimSpace(a.Path) == "" {
		return nil, ReasonSignerOnly
	}
	path := strings.TrimSpace(a.Path)
	if strings.ContainsAny(path, "*?") {
		return nil, ReasonNotAbsolute
	}
	perUser := ""
	for v := range perUserVars {
		if strings.Contains(strings.ToLower(path), "%"+v+"%") {
			perUser = v
			break
		}
	}
	var out []string
	if perUser == "" {
		p, ok := expandVars(path, env)
		if !ok || !isAbs(p) {
			return nil, ReasonNotAbsolute
		}
		return []string{p}, ""
	}
	for _, prof := range profiles {
		e := make(map[string]string, len(env)+len(perUserVars))
		for k, v := range env {
			e[k] = v
		}
		for v, sub := range perUserVars {
			e[v] = prof
			if sub != "" {
				e[v] = prof + `\` + sub
			}
		}
		p, ok := expandVars(path, e)
		if !ok || !isAbs(p) {
			return nil, ReasonNotAbsolute
		}
		out = append(out, p)
	}
	return out, ""
}

// expandVars replaces each %NAME% with env[lower(NAME)]; false when a name
// is unknown or a % is unmatched.
func expandVars(s string, env map[string]string) (string, bool) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			return "", false
		}
		name := strings.ToLower(s[i+1 : i+1+j])
		v, ok := env[name]
		if !ok || v == "" {
			return "", false
		}
		b.WriteString(s[:i])
		b.WriteString(v)
		s = s[i+2+j:]
	}
}

// isAbs reports whether p is an absolute Windows path (C:\… or \\server\…),
// whatever OS the agent is built for, so the logic is tested everywhere.
func isAbs(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return len(p) > 2
	}
	return len(p) >= 3 && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) && p[1] == ':' && p[2] == '\\'
}

// appName names an app in the status: its name, else its path or signer.
func appName(a policy.App) string {
	for _, s := range []string{a.Name, a.Path, a.Signer, a.BundleID} {
		if s != "" {
			return s
		}
	}
	return "?"
}
