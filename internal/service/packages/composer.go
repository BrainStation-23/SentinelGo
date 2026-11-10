package packages

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposerInstalled returns the packages in a Composer
// vendor/composer/installed.json: a plain array (Composer 1) or
// {"packages": [...]} (Composer 2).
func parseComposerInstalled(data []byte) []composerPackage {
	data = bytes.TrimSpace(data)
	var list []composerPackage
	if len(data) > 0 && data[0] == '[' {
		if err := json.Unmarshal(data, &list); err != nil {
			return nil
		}
	} else {
		var v2 struct {
			Packages []composerPackage `json:"packages"`
		}
		if err := json.Unmarshal(data, &v2); err != nil {
			return nil
		}
		list = v2.Packages
	}
	out := list[:0]
	for _, p := range list {
		p.Name = strings.TrimSpace(p.Name)
		p.Version = composerVersion(p.Version)
		if p.Name != "" && p.Version != "" {
			out = append(out, p)
		}
	}
	return out
}

// composerVersion drops the "v" of a tag-style version ("v5.4.1" → "5.4.1"),
// the form Packagist advisories (and OSV) use. Branch versions such as
// "dev-main" are kept as they are.
func composerVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// collectComposerHome reports the packages installed globally with
// `composer global require`, from <home>/vendor/composer/installed.json.
// The location is each package's directory under vendor/.
func (s *scan) collectComposerHome(composerHome, user string) {
	vendor := filepath.Join(composerHome, "vendor")
	data, ok := s.readFile(filepath.Join(vendor, "composer", "installed.json"))
	if !ok {
		return
	}
	for _, p := range parseComposerInstalled(data) {
		s.add(Package{Ecosystem: EcosystemPackagist, Name: p.Name, Version: p.Version,
			Scope: ScopeGlobal, Location: filepath.Join(vendor, filepath.FromSlash(p.Name)), User: user})
	}
}
