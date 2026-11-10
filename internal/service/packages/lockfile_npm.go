package packages

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// nameVersion is one dependency a lockfile pins.
type nameVersion struct{ name, version string }

// parsePackageLock reads package-lock.json / npm-shrinkwrap.json: the
// "packages" map of lockfile v2 and v3 ("node_modules/<name>" keys), else
// the nested "dependencies" tree of v1.
func parsePackageLock(data []byte) []nameVersion {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []nameVersion
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link {
				continue // the root project, a workspace member, or a link to one
			}
			name := p.Name // set for aliases ("node_modules/alias" → the real package)
			if name == "" {
				name = key[i+len("node_modules/"):]
			}
			if v, ok := npmVersion(p.Version); ok && strings.TrimSpace(name) != "" {
				out = append(out, nameVersion{name, v})
			}
		}
		return out
	}
	var walk func(deps map[string]npmV1Dep, depth int)
	walk = func(deps map[string]npmV1Dep, depth int) {
		if depth > 64 {
			return
		}
		for name, d := range deps {
			n, v, ok := npmAliased(name, d.Version)
			if ok && strings.TrimSpace(n) != "" {
				out = append(out, nameVersion{n, v})
			}
			walk(d.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return out
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

// npmAliased resolves a v1 entry whose version is an alias
// ("npm:real-name@1.2.3") to the real package.
func npmAliased(name, version string) (string, string, bool) {
	if rest, ok := strings.CutPrefix(version, "npm:"); ok {
		i := strings.LastIndex(rest, "@")
		if i <= 0 {
			return "", "", false
		}
		name, version = rest[:i], rest[i+1:]
	}
	v, ok := npmVersion(version)
	return name, v, ok
}

// npmVersion accepts a registry version ("1.2.3", "1.0.0-beta.1") and
// rejects git, file, link and tarball specs, which have no registry version
// an advisory could name.
func npmVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, ":/ ") {
		return "", false
	}
	return v, true
}

// parseYarnLock reads yarn.lock, classic (v1) and berry (v2+).
//
// Classic:
//
//	"@babel/core@^7.0.0", "@babel/core@^7.1.0":
//	  version "7.24.0"
//
// Berry:
//
//	"@babel/core@npm:^7.0.0":
//	  version: 7.24.0
//	  resolution: "@babel/core@npm:7.24.0"
//
// Berry entries are taken from their resolution, and only npm: ones count
// (workspace:, patch:, link:, portal: and file: aren't registry packages).
func parseYarnLock(data []byte) []nameVersion {
	var out []nameVersion
	var name, version, resolution string
	inEntry := false
	flush := func() {
		if inEntry {
			if nv, ok := yarnEntry(name, version, resolution); ok {
				out = append(out, nv)
			}
		}
		name, version, resolution, inEntry = "", "", "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "__metadata") {
				inEntry = true
				name = yarnSpecName(line)
			}
			continue
		}
		if !inEntry || strings.HasPrefix(line, "    ") {
			continue // nested maps (dependencies, checksum blocks)
		}
		key, value := yarnField(strings.TrimSpace(line))
		switch key {
		case "version":
			version = value
		case "resolution":
			resolution = value
		}
	}
	flush()
	return out
}

func yarnEntry(name, version, resolution string) (nameVersion, bool) {
	if resolution != "" { // berry
		i := strings.LastIndex(resolution, "@npm:")
		if i <= 0 {
			return nameVersion{}, false
		}
		v, ok := npmVersion(resolution[i+len("@npm:"):])
		return nameVersion{resolution[:i], v}, ok
	}
	v, ok := npmVersion(version)
	if !ok || name == "" {
		return nameVersion{}, false
	}
	return nameVersion{name, v}, true
}

// yarnSpecName takes the package name from an entry header: the first spec,
// without quotes, up to the version range's "@" (a leading "@" is a scope).
// An alias spec ("alias@npm:real@^1") names the real package.
func yarnSpecName(header string) string {
	spec := strings.TrimSuffix(header, ":")
	if i := strings.Index(spec, ","); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.Trim(strings.TrimSpace(spec), `"`)
	if i := strings.Index(spec, "@npm:"); i > 0 {
		spec = spec[i+len("@npm:"):]
	}
	i := strings.LastIndex(spec, "@")
	if i <= 0 {
		return ""
	}
	return spec[:i]
}

// yarnField splits `version "1.2.3"` (classic) or `version: 1.2.3` (berry).
func yarnField(s string) (key, value string) {
	key, value, found := strings.Cut(s, " ")
	if !found {
		return "", ""
	}
	key = strings.TrimSuffix(key, ":")
	return key, strings.Trim(strings.TrimSpace(value), `"`)
}

// parsePnpmLock reads the "packages:" section of pnpm-lock.yaml, versions
// 5 to 9. Keys are "/name/1.2.3" (v5), "/name@1.2.3" (v6) or "name@1.2.3"
// (v9), optionally quoted and with a peer-dependency suffix ("(react@18)"
// or "_react@18"). It reads only the keys, so no YAML library is needed.
func parsePnpmLock(data []byte) []nameVersion {
	var out []nameVersion
	inPackages, v5 := false, false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' {
			if v, ok := strings.CutPrefix(line, "lockfileVersion:"); ok {
				v = strings.Trim(strings.TrimSpace(v), `'"`)
				v5 = v != "" && v[0] >= '0' && v[0] <= '5' && (len(v) == 1 || v[1] == '.')
			}
			inPackages = line == "packages:"
			continue
		}
		// Package keys are indented by exactly two spaces.
		if !inPackages || len(line) < 3 || line[1] != ' ' || line[2] == ' ' {
			continue
		}
		key := strings.TrimSpace(line)
		if !strings.HasSuffix(key, ":") {
			continue
		}
		if nv, ok := pnpmKey(strings.Trim(strings.TrimSuffix(key, ":"), `'"`), v5); ok {
			out = append(out, nv)
		}
	}
	return out
}

// pnpmKey splits a packages key. v5 keys are "/name/version[_peers]";
// later ones are "[/]name@version[(peers)]".
func pnpmKey(key string, v5 bool) (nameVersion, bool) {
	key = strings.TrimPrefix(key, "/")
	sep := "@"
	if v5 {
		sep = "/" // peers are encoded with "+", never "/"
	} else if i := strings.Index(key, "("); i > 0 {
		key = key[:i]
	}
	i := strings.LastIndex(key, sep)
	if i <= 0 {
		return nameVersion{}, false
	}
	name, version := key[:i], key[i+1:]
	if j := strings.Index(version, "_"); v5 && j > 0 {
		version = version[:j]
	}
	v, ok := npmVersion(version)
	if !ok || strings.ContainsAny(name, ": ") {
		return nameVersion{}, false
	}
	return nameVersion{name, v}, true
}
