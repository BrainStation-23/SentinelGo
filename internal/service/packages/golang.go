package packages

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"path/filepath"
	"strings"
	"unicode"
)

// maxGoBinaryBytes caps a go install binary whose build info is read.
// buildinfo reads only the headers and the build-info blob, never the whole
// file, but a huge file in ~/go/bin isn't a Go tool.
const maxGoBinaryBytes = 1 << 30

// goStdlib is the name OSV tracks the Go standard library under.
const goStdlib = "stdlib"

// parseGoModule reads a module's go.mod and go.sum. direct are the
// requirements of go.mod, with its replace directives applied (a module
// replaced by a local path isn't a registry module and is dropped). rest are
// the modules go.sum says were downloaded ("<path> <version> h1:…"; lines
// for "<version>/go.mod" are graph metadata, not a download), without those
// already in direct.
func parseGoModule(mod, sum []byte) (direct, rest []nameVersion) {
	requires, replaces := parseGoMod(mod)
	seen := map[nameVersion]bool{}
	for _, r := range requires {
		nv, ok := r, true
		if to, found := replaces[r]; found {
			nv, ok = to, to.version != ""
		} else if to, found := replaces[nameVersion{r.name, ""}]; found {
			nv, ok = to, to.version != ""
		}
		if ok && goVersion(nv.version) && goModulePath(nv.name) && !seen[nv] {
			seen[nv] = true
			direct = append(direct, nv)
		}
	}
	for _, nv := range parseGoSum(sum) {
		if !seen[nv] {
			seen[nv] = true
			rest = append(rest, nv)
		}
	}
	return direct, rest
}

// parseGoMod returns go.mod's requirements and replacements. A replacement
// keyed with an empty version applies to every version of the module; one
// whose target has an empty version is a local path.
func parseGoMod(data []byte) (requires []nameVersion, replaces map[nameVersion]nameVersion) {
	replaces = map[nameVersion]nameVersion{}
	handle := func(directive string, f []string) {
		switch directive {
		case "require":
			if len(f) == 2 {
				requires = append(requires, nameVersion{goUnquote(f[0]), f[1]})
			}
		case "replace":
			if from, to, ok := goReplace(f); ok {
				replaces[from] = to
			}
		}
	}
	block := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i] // "// indirect" and other comments
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case block != "" && f[0] == ")":
			block = ""
		case block != "":
			handle(block, f)
		case len(f) == 2 && f[1] == "(":
			block = f[0]
		default:
			handle(f[0], f[1:])
		}
	}
	return requires, replaces
}

// goReplace parses "old [v] => new [v]". A target without a version is a
// local path (./x, ../x, /x, C:\x).
func goReplace(f []string) (from, to nameVersion, ok bool) {
	i := -1
	for j, s := range f {
		if s == "=>" {
			i = j
			break
		}
	}
	if i < 1 || i > 2 || len(f)-i-1 < 1 || len(f)-i-1 > 2 {
		return nameVersion{}, nameVersion{}, false
	}
	from.name = goUnquote(f[0])
	if i == 2 {
		from.version = f[1]
	}
	to.name = goUnquote(f[i+1])
	if len(f)-i-1 == 2 {
		to.version = f[i+2]
	}
	return from, to, true
}

func goUnquote(s string) string { return strings.Trim(s, "\"`") }

// parseGoSum returns the modules whose content go.sum records a hash for.
func parseGoSum(data []byte) []nameVersion {
	var out []nameVersion
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || strings.HasSuffix(f[1], "/go.mod") || !goVersion(f[1]) || !goModulePath(f[0]) {
			continue
		}
		out = append(out, nameVersion{f[0], f[1]})
	}
	return out
}

// goVersion accepts a module version as Go writes it: "v1.2.3",
// "v0.0.0-20240101000000-abcdef123456", "v2.0.0+incompatible".
func goVersion(v string) bool {
	return len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' && !strings.ContainsAny(v, " /\\:")
}

// goModulePath accepts a module path: no spaces or control characters,
// and a dot or slash in it (stdlib-like single words aren't modules).
func goModulePath(p string) bool {
	if p == "" || len(p) > maxNameLen {
		return false
	}
	for _, c := range p {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return strings.ContainsAny(p, "./")
}

// goBinaryModules returns what a go install binary was built from: its main
// module (when it has a release version), its dependencies (replacements
// applied; local replacements dropped) and the standard library at the
// binary's Go version.
func goBinaryModules(bi *buildinfo.BuildInfo) []nameVersion {
	var out []nameVersion
	if goVersion(bi.Main.Version) && goModulePath(bi.Main.Path) {
		out = append(out, nameVersion{bi.Main.Path, bi.Main.Version})
	}
	for _, d := range bi.Deps {
		if d.Replace != nil {
			d = d.Replace
		}
		if goVersion(d.Version) && goModulePath(d.Path) {
			out = append(out, nameVersion{d.Path, d.Version})
		}
	}
	// "go1.22.1" or "go1.22.1 X:boringcrypto"; OSV's stdlib versions have no
	// "go" prefix. A development toolchain ("devel …") names no release.
	if f := strings.Fields(bi.GoVersion); len(f) > 0 {
		if v, ok := strings.CutPrefix(f[0], "go"); ok && v != "" && v[0] >= '0' && v[0] <= '9' {
			out = append(out, nameVersion{goStdlib, v})
		}
	}
	return out
}

// collectGoBin reports the binaries `go install` put in a folder (GOBIN, by
// default ~/go/bin): the build info embedded in each is read without running
// it. The location is the binary.
func (s *scan) collectGoBin(dir, user string) {
	for _, e := range s.readDir(dir) {
		if !e.Type().IsRegular() || s.stopped() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil || info.Size() > maxGoBinaryBytes || placeholder(info) {
			continue
		}
		s.files++
		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			continue // not a Go binary (a script, a symlinked tool)
		}
		for _, nv := range goBinaryModules(bi) {
			s.add(Package{Ecosystem: EcosystemGo, Name: nv.name, Version: nv.version,
				Scope: ScopeGlobal, Location: path, User: user})
		}
	}
}

// collectGoModCache reports the module download cache
// (GOMODCACHE/cache/download/<escaped path>/@v/<version>.zip): the modules
// whose source was downloaded. Upper-case letters are escaped there as
// "!" plus the lower-case letter. The location is the zip.
func (s *scan) collectGoModCache(dir, user string) {
	var walk func(d string, segs []string)
	walk = func(d string, segs []string) {
		if len(segs) > maxMavenDepth || s.stopped() {
			return
		}
		for _, e := range s.readDir(d) {
			name := e.Name()
			if !isDir(e) {
				continue
			}
			sub := filepath.Join(d, name)
			if name != "@v" {
				if !strings.HasPrefix(name, ".") && name != "sumdb" {
					walk(sub, append(segs[:len(segs):len(segs)], name))
				}
				continue
			}
			module, ok := goUnescape(strings.Join(segs, "/"))
			if !ok || !goModulePath(module) {
				continue
			}
			for _, f := range s.regularFiles(sub) {
				v, found := strings.CutSuffix(f, ".zip")
				if !found {
					continue
				}
				if v, ok := goUnescape(v); ok && goVersion(v) {
					s.add(Package{Ecosystem: EcosystemGo, Name: module, Version: v,
						Scope: ScopeCache, Location: filepath.Join(sub, f), User: user})
				}
			}
		}
	}
	walk(dir, nil)
}

// goUnescape undoes the module cache's case escaping ("!x" is "X"). An
// upper-case letter or a "!" not followed by a lower-case letter means the
// name isn't an escaped path.
func goUnescape(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '!':
			if i+1 >= len(s) || s[i+1] < 'a' || s[i+1] > 'z' {
				return "", false
			}
			i++
			b.WriteByte(s[i] - 'a' + 'A')
		case c >= 'A' && c <= 'Z':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}
