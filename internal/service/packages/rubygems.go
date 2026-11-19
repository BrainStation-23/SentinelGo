package packages

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// parseGemfileLock reads Gemfile.lock (and gems.locked): the "specs:"
// entries of each GEM section, "    name (version)" at four spaces (six
// spaces are a gem's own dependencies). GIT and PATH sections aren't
// RubyGems releases and are skipped. A platform suffix is dropped
// ("1.15.0-x86_64-linux" is release 1.15.0).
func parseGemfileLock(data []byte) []nameVersion {
	var out []nameVersion
	inGem, inSpecs := false, false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' {
			inGem, inSpecs = line == "GEM", false
			continue
		}
		if !inGem {
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(line), " (")
		version, closed := strings.CutSuffix(rest, ")")
		if !ok || !closed {
			continue
		}
		if v, ok := gemVersion(version); ok && gemName(name) {
			out = append(out, nameVersion{name, v})
		}
	}
	return out
}

// gemVersion drops a platform suffix and accepts a release
// ("1.15.0", "7.1.0.rc1").
func gemVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " ,<>=~!/\\:") {
		return "", false
	}
	return v, true
}

// gemName accepts a gem name (letters, digits, "-", "_", ".").
func gemName(n string) bool { return nameChars(n, "-_.") }

// gemspecFileName splits "<name>-<version>[-<platform>].gemspec". Gem
// names may contain "-", so the version is the first segment that starts
// with a digit.
func gemspecFileName(file string) (nameVersion, bool) {
	base, ok := strings.CutSuffix(file, ".gemspec")
	if !ok {
		return nameVersion{}, false
	}
	segs := strings.Split(base, "-")
	for i := 1; i < len(segs); i++ {
		if segs[i] == "" || segs[i][0] < '0' || segs[i][0] > '9' {
			continue
		}
		name := strings.Join(segs[:i], "-")
		if v, ok := gemVersion(segs[i]); ok && gemName(name) {
			return nameVersion{name, v}, true
		}
		return nameVersion{}, false
	}
	return nameVersion{}, false
}

// collectGemDir reports the gems installed in a GEM_HOME from the file
// names in specifications/ (and specifications/default/, the default gems
// that ship with Ruby, which have their own advisories). The gemspecs are
// Ruby code and are never read. The location is the gemspec.
func (s *scan) collectGemDir(dir, user string) {
	for _, specs := range []string{filepath.Join(dir, "specifications"), filepath.Join(dir, "specifications", "default")} {
		for _, f := range s.regularFiles(specs) {
			if nv, ok := gemspecFileName(f); ok {
				s.add(Package{Ecosystem: EcosystemRubyGems, Name: nv.name, Version: nv.version,
					Scope: ScopeGlobal, Location: filepath.Join(specs, f), User: user})
			}
		}
	}
}
