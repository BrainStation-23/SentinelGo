package packages

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// parsePackageJSON returns the name and version a package.json declares.
func parsePackageJSON(data []byte) (name, version string, ok bool) {
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", false
	}
	name, version = strings.TrimSpace(m.Name), strings.TrimSpace(m.Version)
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// collectNodeModules reports each package directly inside a global
// node_modules directory: <dir>/<pkg>/package.json and
// <dir>/@scope/<pkg>/package.json. Nested node_modules are the packages'
// own dependencies and are not walked.
func (s *scan) collectNodeModules(dir, user string) {
	for _, e := range s.readDir(dir) {
		name := e.Name()
		if !isDir(e) || strings.HasPrefix(name, ".") {
			continue // .bin, .package-lock.json, links
		}
		if strings.HasPrefix(name, "@") {
			scopeDir := filepath.Join(dir, name)
			for _, se := range s.readDir(scopeDir) {
				if isDir(se) && !strings.HasPrefix(se.Name(), ".") {
					s.addNPM(filepath.Join(scopeDir, se.Name()), user)
				}
			}
			continue
		}
		s.addNPM(filepath.Join(dir, name), user)
	}
}

func (s *scan) addNPM(pkgDir, user string) {
	data, ok := s.readFile(filepath.Join(pkgDir, "package.json"))
	if !ok {
		return
	}
	name, version, ok := parsePackageJSON(data)
	if !ok {
		return
	}
	s.add(Package{Ecosystem: EcosystemNPM, Name: name, Version: version,
		Scope: ScopeGlobal, Location: pkgDir, User: user})
}
