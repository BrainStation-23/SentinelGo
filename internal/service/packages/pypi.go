package packages

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// parseCoreMetadata returns Name and Version from a Python core metadata
// file (a dist-info METADATA or an egg-info PKG-INFO). The headers are
// RFC 822 style and end at the first blank line, where the description body
// starts.
func parseCoreMetadata(data []byte) (name, version string, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			if name == "" {
				name = strings.TrimSpace(value)
			}
		case "version":
			if version == "" {
				version = strings.TrimSpace(value)
			}
		}
		if name != "" && version != "" {
			return name, version, true
		}
	}
	return "", "", false
}

// collectSitePackages reports each distribution installed in a
// site-packages (or dist-packages) directory: *.dist-info/METADATA (wheels,
// modern pip) and *.egg-info/PKG-INFO or a *.egg-info file (older installs).
// The location is the distribution's metadata directory, which is unique per
// installed distribution.
func (s *scan) collectSitePackages(dir, user string) {
	for _, e := range s.readDir(dir) {
		name := e.Name()
		var meta string
		switch {
		case strings.HasSuffix(name, ".dist-info") && isDir(e):
			meta = filepath.Join(dir, name, "METADATA")
		case strings.HasSuffix(name, ".egg-info") && isDir(e):
			meta = filepath.Join(dir, name, "PKG-INFO")
		case strings.HasSuffix(name, ".egg-info") && e.Type().IsRegular():
			meta = filepath.Join(dir, name)
		default:
			continue
		}
		data, ok := s.readFile(meta)
		if !ok {
			continue
		}
		pkgName, version, ok := parseCoreMetadata(data)
		if !ok {
			continue
		}
		s.add(Package{Ecosystem: EcosystemPyPI, Name: pkgName, Version: version,
			Scope: ScopeGlobal, Location: filepath.Join(dir, name), User: user})
	}
}
