package packages

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// crates.io's index, as Cargo.lock names it: the git index, or the sparse
// protocol. Other registries aren't crates.io, so OSV's crates.io advisories
// don't apply to them.
var cratesIOSources = map[string]bool{
	"registry+https://github.com/rust-lang/crates.io-index": true,
	"sparse+https://index.crates.io/":                       true,
}

// parseCargoLock reads Cargo.lock: [[package]] tables with name, version
// and source. Path and git dependencies (and the workspace's own crates,
// which have no source) aren't on crates.io and are skipped.
func parseCargoLock(data []byte) []nameVersion {
	var out []nameVersion
	for _, t := range tomlArrayTables(data, "package") {
		if !cratesIOSources[t.keys["source"]] {
			continue
		}
		if v, ok := cargoVersion(t.keys["version"]); ok && crateName(t.keys["name"]) {
			out = append(out, nameVersion{t.keys["name"], v})
		}
	}
	return out
}

// parseCargoInstalls reads ~/.cargo/.crates2.json, cargo install's record:
// {"installs": {"<name> <version> (<source>)": {…}}}.
func parseCargoInstalls(data []byte) []nameVersion {
	var f struct {
		Installs map[string]json.RawMessage `json:"installs"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil
	}
	var out []nameVersion
	for key := range f.Installs {
		if nv, ok := cargoInstallKey(key); ok {
			out = append(out, nv)
		}
	}
	return out
}

// parseCargoInstallsTOML reads the older ~/.cargo/.crates.toml:
// [v1] "<name> <version> (<source>)" = ["bin", …].
func parseCargoInstallsTOML(data []byte) []nameVersion {
	var out []nameVersion
	inV1 := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[\"") {
			inV1 = line == "[v1]"
			continue
		}
		if !inV1 || !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			continue
		}
		if nv, ok := cargoInstallKey(line[1 : end+1]); ok {
			out = append(out, nv)
		}
	}
	return out
}

// cargoInstallKey splits "<name> <version> (<source>)". Only crates.io
// installs count; a git or path install has no crates.io release.
func cargoInstallKey(key string) (nameVersion, bool) {
	f := strings.Fields(key)
	if len(f) != 3 {
		return nameVersion{}, false
	}
	source := strings.TrimSuffix(strings.TrimPrefix(f[2], "("), ")")
	v, ok := cargoVersion(f[1])
	if !ok || !crateName(f[0]) || !cratesIOSources[source] {
		return nameVersion{}, false
	}
	return nameVersion{f[0], v}, true
}

// crateFileName splits "<name>-<version>.crate" at the last "-" that is
// followed by a digit: crate names may contain "-", versions start with a
// digit (and may contain "-" only after the patch number).
func crateFileName(file string) (nameVersion, bool) {
	base, ok := strings.CutSuffix(file, ".crate")
	if !ok {
		return nameVersion{}, false
	}
	for i := len(base) - 2; i > 0; i-- {
		if base[i] != '-' || base[i+1] < '0' || base[i+1] > '9' {
			continue
		}
		// The version is the first "-<digit>" after which the rest parses
		// as a version (1.0.0-beta.1 contains "-b", not "-<digit>").
		name, version := base[:i], base[i+1:]
		if v, vok := cargoVersion(version); vok && crateName(name) && strings.Count(version, ".") >= 2 {
			return nameVersion{name, v}, true
		}
	}
	return nameVersion{}, false
}

// cargoVersion accepts a semver release ("1.0.197", "0.3.0-alpha.1").
func cargoVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " /\\:()") {
		return "", false
	}
	return v, true
}

// crateName accepts a crate name (letters, digits, "-", "_").
func crateName(n string) bool { return nameChars(n, "-_") }

// collectCargoHome reports what `cargo install` installed, from the Cargo
// home's .crates2.json (or, before Cargo 1.41, .crates.toml). The location
// is that file.
func (s *scan) collectCargoHome(home, user string) {
	for _, f := range []struct {
		name  string
		parse func([]byte) []nameVersion
	}{{".crates2.json", parseCargoInstalls}, {".crates.toml", parseCargoInstallsTOML}} {
		path := filepath.Join(home, f.name)
		data, ok := s.readFile(path)
		if !ok {
			continue
		}
		for _, nv := range f.parse(data) {
			s.add(Package{Ecosystem: EcosystemCargo, Name: nv.name, Version: nv.version,
				Scope: ScopeGlobal, Location: path, User: user})
		}
		return // .crates2.json supersedes .crates.toml
	}
}

// cratesIOGitCache is the cache folder of crates.io's git index. Other
// registries hosted on GitHub also get a "github.com-<hash>" folder, so only
// this hash counts.
const cratesIOGitCache = "github.com-1ecc6299db9ec823"

// collectCargoCache reports a registry's download cache
// (~/.cargo/registry/cache/<index>/<name>-<version>.crate). Only the
// crates.io index folders count: "index.crates.io-<hash>" (the sparse
// protocol; another sparse registry is named after its own host) and the
// git index's. A private registry's crates never leave the device. The
// location is the .crate file.
func (s *scan) collectCargoCache(dir, user string) {
	base := filepath.Base(dir)
	if !strings.HasPrefix(base, "index.crates.io-") && base != cratesIOGitCache {
		return
	}
	for _, f := range s.regularFiles(dir) {
		if nv, ok := crateFileName(f); ok {
			s.add(Package{Ecosystem: EcosystemCargo, Name: nv.name, Version: nv.version,
				Scope: ScopeCache, Location: filepath.Join(dir, f), User: user})
		}
	}
}
