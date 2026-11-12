package packages

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// parseTOMLPackages reads the [[package]] tables of poetry.lock and
// uv.lock: their name and version keys. Packages installed from a local
// path (the project itself, editable or path dependencies) are skipped:
// they aren't registry packages. It reads only these keys, so no TOML
// library is needed.
func parseTOMLPackages(data []byte) []nameVersion {
	var out []nameVersion
	var name, version string
	local, inPackage, inSource := false, false, false
	flush := func() {
		if inPackage && name != "" && !local {
			if v, ok := pyVersion(version); ok {
				out = append(out, nameVersion{name, v})
			}
		}
		name, version, local, inPackage, inSource = "", "", false, false, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			switch {
			case line == "[[package]]":
				flush()
				inPackage = true
			case line == "[package.source]": // poetry
				inSource = inPackage
			case strings.HasPrefix(line, "[package.") || strings.HasPrefix(line, "[[package."):
				inSource = false // other subtables of the same package
			default:
				flush()
			}
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := tomlKeyValue(line)
		if !ok {
			continue
		}
		switch {
		case inSource && key == "type": // poetry: directory, file, git, url, legacy
			local = local || value == "directory" || value == "file"
		case inSource:
		case key == "name":
			name = value
		case key == "version":
			version = value
		case key == "source": // uv: { registry = … } or { editable = "." } …
			local = local || uvLocalSource(value)
		}
	}
	flush()
	return out
}

// uvLocalSource reports whether a uv source table is a local one:
// { editable = "." }, { virtual = "." }, { directory = … } or { path = … }.
func uvLocalSource(table string) bool {
	table = strings.Trim(table, "{} ")
	for field := range strings.SplitSeq(table, ",") {
		key, _, _ := strings.Cut(field, "=")
		switch strings.TrimSpace(key) {
		case "editable", "virtual", "directory", "path":
			return true
		}
	}
	return false
}

// tomlKeyValue splits `key = "value"` (a basic string) or `key = { … }`.
func tomlKeyValue(line string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' {
		if end := strings.IndexByte(value[1:], '"'); end >= 0 {
			value = value[1 : end+1]
		}
	}
	return key, value, true
}

// pyVersion accepts a release version (PEP 440 starts with a digit, or an
// epoch such as "1!2.0").
func pyVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " /:@") {
		return "", false
	}
	return v, true
}

// parsePipfileLock reads Pipfile.lock: "default" and "develop" map names to
// {"version": "==1.2.3"}. Entries without a pinned version (git, editable,
// path) are skipped.
func parsePipfileLock(data []byte) []nameVersion {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []nameVersion
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(lock[section], &deps); err != nil {
			continue
		}
		for name, d := range deps {
			if v, ok := pyVersion(strings.TrimPrefix(d.Version, "==")); ok && strings.TrimSpace(name) != "" {
				out = append(out, nameVersion{name, v})
			}
		}
	}
	return out
}

// parseRequirements reads a pip requirements file and keeps the pinned
// lines ("name==1.2.3", "name[extra]===1.2.3; marker  # comment"). Options
// (-r, -e, --hash …), URLs and unpinned ranges are skipped: they don't name
// one installed version.
func parseRequirements(data []byte) []nameVersion {
	var out []nameVersion
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexAny(line, ";\\"); i >= 0 {
			line = line[:i] // environment marker, or a line continuation (--hash follows)
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '-' {
			continue
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		version = strings.TrimPrefix(version, "=") // ===
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		v, ok := pyVersion(strings.TrimSpace(version))
		if !ok || name == "" || strings.ContainsAny(name, " /:@<>!~=,") || strings.ContainsAny(v, ",*") {
			continue
		}
		out = append(out, nameVersion{name, v})
	}
	return out
}

// parseComposerLock reads composer.lock: "packages" and "packages-dev".
func parseComposerLock(data []byte) []nameVersion {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []nameVersion
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		name, version := strings.TrimSpace(p.Name), composerVersion(p.Version)
		if name != "" && version != "" {
			out = append(out, nameVersion{name, version})
		}
	}
	return out
}
