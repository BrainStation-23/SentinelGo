package packages

import (
	"encoding/json"
	"io/fs"
	"os"
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

func (s *scan) addNPM(pkgDir, user string) { s.addNPMFrom(pkgDir, pkgDir, user) }

// addNPMFrom reports the package.json in pkgDir, located at location.
func (s *scan) addNPMFrom(pkgDir, location, user string) {
	data, ok := s.readFile(filepath.Join(pkgDir, "package.json"))
	if !ok {
		return
	}
	name, version, ok := parsePackageJSON(data)
	if !ok {
		return
	}
	s.add(Package{Ecosystem: EcosystemNPM, Name: name, Version: version,
		Scope: ScopeGlobal, Location: location, User: user})
}

// collectPnpmGlobal reports the packages of a pnpm global install
// (pnpm add -g): <PNPM_HOME>/global/<layout>/node_modules. Its top-level
// entries are links (symlinks; junctions on Windows) into pnpm's virtual
// store in node_modules/.pnpm. A link is followed only when it resolves
// inside that node_modules, so it can't lead to a user's project or another
// drive. The location is the link.
func (s *scan) collectPnpmGlobal(dir, user string) {
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return
	}
	var visit func(d string, scoped bool)
	visit = func(d string, scoped bool) {
		for _, e := range s.readDir(d) {
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue // .pnpm (the store itself), .bin, .modules.yaml
			}
			p := filepath.Join(d, name)
			if e.Type()&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
				switch {
				case !e.IsDir():
				case !scoped && strings.HasPrefix(name, "@"):
					visit(p, true)
				default:
					s.addNPM(p, user) // node-linker=hoisted: a real folder
				}
				continue
			}
			target, err := filepath.EvalSymlinks(p)
			if err != nil || !pathHasPrefix(target, realDir) {
				continue
			}
			if info, err := os.Stat(target); err == nil && info.IsDir() {
				s.addNPMFrom(target, p, user)
			}
		}
	}
	visit(dir, false)
}
