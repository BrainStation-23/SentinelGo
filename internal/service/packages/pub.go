package packages

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// pubHosts are the URLs of pub.dev, the registry OSV's Pub advisories cover.
var pubHosts = map[string]bool{"https://pub.dev": true, "https://pub.dartlang.org": true}

// parsePubspecLock reads pubspec.lock: packages.<name> with source and
// version. Only "hosted" packages from pub.dev count; git, path and sdk
// packages, and other hosted registries, aren't pub.dev releases. It reads
// the fixed layout `dart pub` writes, so no YAML library is needed.
func parsePubspecLock(data []byte) []nameVersion {
	var out []nameVersion
	inPackages := false
	var name, descName, source, version, url string
	flush := func() {
		if name != "" && source == "hosted" && (url == "" || pubHosts[strings.TrimSuffix(url, "/")]) {
			n := name
			if descName != "" {
				n = descName
			}
			if v, ok := pubVersion(version); ok && pubName(n) {
				out = append(out, nameVersion{n, v})
			}
		}
		name, descName, source, version, url = "", "", "", "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch indent {
		case 0:
			flush()
			inPackages = key == "packages"
		case 2:
			if inPackages {
				flush()
				name = strings.Trim(key, `"'`)
			}
		case 4:
			switch key {
			case "source":
				source = value
			case "version":
				version = value
			}
		case 6:
			switch key {
			case "name":
				descName = value
			case "url":
				url = value
			}
		}
	}
	flush()
	return out
}

// pubVersion accepts a semver release ("2.11.0", "1.0.0-dev.3").
func pubVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " /\\:<>=^") {
		return "", false
	}
	return v, true
}

// pubName accepts a Dart package name (lower-case letters, digits, "_").
func pubName(n string) bool { return nameChars(n, "_") && strings.ToLower(n) == n }

// collectPubGlobal reports a package activated with `dart pub global
// activate`: <pub cache>/global_packages/<package>/pubspec.lock lists the
// package and its dependencies. The location is that lockfile.
func (s *scan) collectPubGlobal(dir, user string) {
	path := filepath.Join(dir, "pubspec.lock")
	data, ok := s.readFile(path)
	if !ok {
		return
	}
	for _, nv := range parsePubspecLock(data) {
		s.add(Package{Ecosystem: EcosystemPub, Name: nv.name, Version: nv.version,
			Scope: ScopeGlobal, Location: path, User: user})
	}
}

// collectPubCache reports the Pub cache's hosted packages
// (<pub cache>/hosted/pub.dev/<name>-<version>/). Package names have no
// "-", so the first one splits name and version. The location is the
// package folder.
func (s *scan) collectPubCache(dir, user string) {
	for _, d := range s.subdirs(dir) {
		name, version, ok := strings.Cut(d, "-")
		if !ok {
			continue
		}
		if v, vok := pubVersion(version); vok && pubName(name) {
			s.add(Package{Ecosystem: EcosystemPub, Name: name, Version: v,
				Scope: ScopeCache, Location: filepath.Join(dir, d), User: user})
		}
	}
}

// mixHexEntry matches a mix.lock line for a Hex package:
//
//	"jason": {:hex, :jason, "1.4.1", "<checksum>", [:mix], [...], "hexpm", "<checksum>"},
//
// The second element is the package's name on Hex (the key may be an
// alias). Elixir terms aren't parsed beyond this strict pattern.
var mixHexEntry = regexp.MustCompile(`^\s*"[^"]+":\s*\{:hex,\s*:"?([a-z0-9_]+)"?,\s*"([0-9][^"\s]*)"`)

// mixRepo matches the repository element at the end of a Hex entry
// (`…, "hexpm", "<checksum>"},`; older mix.lock files end at the
// repository). A dependency's repo: option inside the entry isn't at the
// end, so it never matches.
var mixRepo = regexp.MustCompile(`"(hexpm[^"]*)"(?:,\s*"[0-9a-fA-F]*")?\s*\},?\s*$`)

// parseMixLock reads mix.lock. Only :hex entries count (:git and :path
// aren't Hex releases), and only from the public repository: a package
// from a private organisation ("hexpm:<org>") isn't on hex.pm.
func parseMixLock(data []byte) []nameVersion {
	var out []nameVersion
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		m := mixHexEntry.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if r := mixRepo.FindStringSubmatch(line); r != nil && r[1] != "hexpm" {
			continue
		}
		if v, ok := pubVersion(m[2]); ok {
			out = append(out, nameVersion{m[1], v})
		}
	}
	return out
}
