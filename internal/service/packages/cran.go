package packages

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

// cranRepositories are the repository names that serve CRAN's packages:
// CRAN itself and Posit's Package Manager mirror of it (renv records it as
// RSPM, newer versions as P3M or PPM).
var cranRepositories = map[string]bool{"cran": true, "rspm": true, "p3m": true, "ppm": true}

// parseRenvLock reads renv.lock: Packages.<name> with Package, Version,
// Source and Repository. Only packages installed from a CRAN repository
// count; Bioconductor, GitHub and local packages aren't CRAN releases.
func parseRenvLock(data []byte) []nameVersion {
	var lock struct {
		R struct {
			Repositories []struct {
				Name string `json:"Name"`
				URL  string `json:"URL"`
			} `json:"Repositories"`
		} `json:"R"`
		Packages map[string]struct {
			Package    string `json:"Package"`
			Version    string `json:"Version"`
			Source     string `json:"Source"`
			Repository string `json:"Repository"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	cran := map[string]bool{}
	for name := range cranRepositories {
		cran[name] = true
	}
	for _, r := range lock.R.Repositories {
		if cranURL(r.URL) {
			cran[strings.ToLower(r.Name)] = true
		}
	}
	var out []nameVersion
	for key, p := range lock.Packages {
		if p.Source != "Repository" || !cran[strings.ToLower(p.Repository)] {
			continue
		}
		name := firstNonEmpty(p.Package, key)
		if v, ok := cranVersion(p.Version); ok && cranName(name) {
			out = append(out, nameVersion{name, v})
		}
	}
	return out
}

// cranURL reports whether a repository URL is CRAN or a mirror of it.
func cranURL(u string) bool {
	u = strings.ToLower(u)
	return strings.Contains(u, "cran") || strings.Contains(u, "packagemanager.posit.co") ||
		strings.Contains(u, "packagemanager.rstudio.com")
}

// parseDescription reads an installed R package's DESCRIPTION (Debian
// control format) and returns its name and version when it came from CRAN
// ("Repository: CRAN", or RSPM for Posit's mirror). Base packages
// ("Priority: base") ship with R itself.
func parseDescription(data []byte) (name, version string, ok bool) {
	var repository, priority string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue // a continuation line
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			name = value
		case "Version":
			version = value
		case "Repository":
			repository = value
		case "Priority":
			priority = value
		}
	}
	if priority == "base" || !cranRepositories[strings.ToLower(repository)] {
		return "", "", false
	}
	v, vok := cranVersion(version)
	if !vok || !cranName(name) {
		return "", "", false
	}
	return name, v, true
}

// cranVersion accepts an R package version ("1.1-4", "3.5.1").
func cranVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " /\\:<>=,()") {
		return "", false
	}
	return v, true
}

// cranName accepts an R package name (letters, digits, ".").
func cranName(n string) bool { return nameChars(n, ".") }

// collectRLibrary reports the CRAN packages in an R library
// (<library>/<package>/DESCRIPTION). The location is the package folder.
func (s *scan) collectRLibrary(lib, user string) {
	for _, d := range s.subdirs(lib) {
		pkgDir := filepath.Join(lib, d)
		data, ok := s.readFile(filepath.Join(pkgDir, "DESCRIPTION"))
		if !ok {
			continue
		}
		if name, version, ok := parseDescription(data); ok {
			s.add(Package{Ecosystem: EcosystemCRAN, Name: name, Version: version,
				Scope: ScopeGlobal, Location: pkgDir, User: user})
		}
	}
}
