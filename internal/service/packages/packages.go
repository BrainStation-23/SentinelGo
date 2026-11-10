// Package packages reports the npm, PyPI and Composer packages installed on
// the device (#421), so the backend can say which devices have a given
// name@version when a malicious release is published (supply-chain worms).
//
// It only reads files: it never runs npm, pip or composer, so collecting
// starts no child process and makes no network call. Uploads go through
// agent_enqueue_packages, separate from the software inventory (volume is far
// higher, and the server keeps packages out of the software catalog). The
// server decides whether anything is collected (agent_get_package_settings,
// off by default).
//
// Contract: Compliance-OS docs/agent-ingestion.md, "Packages (#798)".
package packages

import (
	"cmp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Ecosystems, as the server names them.
const (
	EcosystemNPM       = "npm"
	EcosystemPyPI      = "pypi"
	EcosystemPackagist = "packagist"
)

// Scopes: a global install (location is the install directory) or a project
// dependency (location is the lockfile).
const (
	ScopeGlobal  = "global"
	ScopeProject = "project"
)

// Server-side limits on a row (characters). A row over any of them is
// rejected by the server, and one rejected row stops a full snapshot from
// retiring removed packages, so the agent drops such rows itself.
const (
	maxNameLen     = 214 // npm's own limit on package names
	maxVersionLen  = 128
	maxLocationLen = 1024
	maxUserLen     = 256
)

// Package is one installed package. Its identity is
// (Ecosystem, Name, Version, Location).
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Scope     string `json:"scope"`
	Location  string `json:"location"`
	// User is the OS account the package belongs to; empty for system-wide
	// installs.
	User string `json:"user,omitempty"`
}

type identity struct{ ecosystem, name, version, location string }

func (p Package) id() identity {
	return identity{p.Ecosystem, p.Name, p.Version, p.Location}
}

// valid reports whether the server would store p. Values are trimmed first,
// as the server trims them.
func (p *Package) valid() bool {
	p.Name = strings.TrimSpace(p.Name)
	p.Version = strings.TrimSpace(p.Version)
	p.Location = strings.TrimSpace(p.Location)
	p.User = strings.TrimSpace(p.User)
	switch {
	case p.Ecosystem != EcosystemNPM && p.Ecosystem != EcosystemPyPI && p.Ecosystem != EcosystemPackagist:
		return false
	case p.Scope != ScopeGlobal && p.Scope != ScopeProject:
		return false
	case !lenOK(p.Name, maxNameLen), !lenOK(p.Version, maxVersionLen), !lenOK(p.Location, maxLocationLen):
		return false
	case utf8.RuneCountInString(p.User) > maxUserLen:
		return false
	}
	return utf8.ValidString(p.Name) && utf8.ValidString(p.Version) &&
		utf8.ValidString(p.Location) && utf8.ValidString(p.User)
}

// lenOK reports whether s is non-empty and at most n characters.
func lenOK(s string, n int) bool {
	return s != "" && utf8.RuneCountInString(s) <= n
}

// normalize drops rows the server would reject and duplicates, and sorts the
// rest, so equal inventories hash the same. It returns the number dropped as
// invalid.
func normalize(in []Package) (out []Package, invalid int) {
	seen := make(map[identity]bool, len(in))
	out = make([]Package, 0, len(in))
	for _, p := range in {
		if !p.valid() {
			invalid++
			continue
		}
		if seen[p.id()] {
			continue
		}
		seen[p.id()] = true
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Package) int {
		return cmp.Or(
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Location, b.Location),
		)
	})
	return out, invalid
}
