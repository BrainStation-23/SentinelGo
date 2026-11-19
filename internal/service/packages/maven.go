package packages

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// maxMavenDepth bounds the walk of a Maven local repository: group paths
// rarely have more than six segments (org/apache/maven/plugins/…).
const maxMavenDepth = 16

// parseGradleLockfile reads gradle.lockfile and buildscript-gradle.lockfile:
// "group:artifact:version=configuration,…" lines. "empty=…" and comments
// carry no dependency.
func parseGradleLockfile(data []byte) []nameVersion {
	var out []nameVersion
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		coords, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coords, ":")
		if len(parts) != 3 {
			continue
		}
		if nv, ok := mavenCoordinate(parts[0], parts[1], parts[2]); ok {
			out = append(out, nv)
		}
	}
	return out
}

// pom is the part of a pom.xml read here.
type pom struct {
	GroupID string `xml:"groupId"`
	Version string `xml:"version"`
	Parent  struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"dependencies>dependency"`
}

// parsePom reads the direct dependencies of a pom.xml: those with a literal
// version, or a ${property} defined in the same file (or the project's own
// version). Versions managed by a parent or a BOM, and ranges, aren't
// resolved: Maven has no lockfile, so these are what the project declares,
// not the full resolved graph.
func parsePom(data []byte) []nameVersion {
	var p pom
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	if err := dec.Decode(&p); err != nil {
		return nil
	}
	props := map[string]string{}
	for _, e := range p.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	groupID := firstNonEmpty(p.GroupID, p.Parent.GroupID)
	version := firstNonEmpty(p.Version, p.Parent.Version)
	for k, v := range map[string]string{
		"project.groupId": groupID, "pom.groupId": groupID,
		"project.version": version, "pom.version": version,
		"project.parent.version": p.Parent.Version,
	} {
		if v != "" {
			props[k] = v
		}
	}
	var out []nameVersion
	for _, d := range p.Dependencies {
		if nv, ok := mavenCoordinate(pomValue(d.GroupID, props), pomValue(d.ArtifactID, props), pomValue(d.Version, props)); ok {
			out = append(out, nv)
		}
	}
	return out
}

// pomValue resolves a value that is wholly one ${property}; other values
// are returned as they are.
func pomValue(v string, props map[string]string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return props[v[2:len(v)-1]]
	}
	return v
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// mavenCoordinate builds the "groupId:artifactId" name. Unresolved
// properties, ranges ("[1.0,2.0)") and dynamic versions ("1.+", "latest")
// aren't one version an advisory could name.
func mavenCoordinate(group, artifact, version string) (nameVersion, bool) {
	group, artifact, version = strings.TrimSpace(group), strings.TrimSpace(artifact), strings.TrimSpace(version)
	if !mavenPart(group) || !mavenPart(artifact) || !mavenVersion(version) {
		return nameVersion{}, false
	}
	return nameVersion{group + ":" + artifact, version}, true
}

func mavenPart(s string) bool { return nameChars(s, ".-_") }

func mavenVersion(v string) bool {
	return v != "" && !strings.ContainsAny(v, " ,()[]${}+*/\\:") &&
		!strings.EqualFold(v, "latest") && !strings.EqualFold(v, "release")
}

// collectMavenRepo reports a Maven local repository: each
// <group path>/<artifact>/<version>/ folder that holds that version's .pom
// or .jar ("<artifact>-<version>.pom"). Group path segments join with ".".
// The location is the version folder.
func (s *scan) collectMavenRepo(repo, user string) {
	var walk func(dir string, segs []string)
	walk = func(dir string, segs []string) {
		if len(segs) > maxMavenDepth || s.stopped() {
			return
		}
		entries := s.readDir(dir)
		if n := len(segs); n >= 3 {
			group, artifact, version := strings.Join(segs[:n-2], "."), segs[n-2], segs[n-1]
			prefix := artifact + "-" + version
			for _, e := range entries {
				name := e.Name()
				if e.Type().IsRegular() && strings.HasPrefix(name, prefix) &&
					(strings.HasSuffix(name, ".pom") || strings.HasSuffix(name, ".jar")) {
					if nv, ok := mavenCoordinate(group, artifact, version); ok {
						s.add(Package{Ecosystem: EcosystemMaven, Name: nv.name, Version: nv.version,
							Scope: ScopeCache, Location: dir, User: user})
					}
					return // a version folder has no artifacts below it
				}
			}
		}
		for _, e := range entries {
			if isDir(e) && !strings.HasPrefix(e.Name(), ".") {
				walk(filepath.Join(dir, e.Name()), append(segs[:len(segs):len(segs)], e.Name()))
			}
		}
	}
	walk(repo, nil)
}

// collectM2Settings reads the localRepository a Maven settings.xml sets,
// and reports that repository when it is an absolute path on a local drive
// other than the default one (which has its own root).
func (s *scan) collectM2Settings(settingsFile, user string) {
	data, ok := s.readFile(settingsFile)
	if !ok {
		return
	}
	var settings struct {
		LocalRepository string `xml:"localRepository"`
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	if dec.Decode(&settings) != nil {
		return
	}
	repo := filepath.Clean(strings.TrimSpace(settings.LocalRepository))
	if !filepath.IsAbs(repo) || strings.Contains(repo, "${") {
		return
	}
	if sameFold(repo, filepath.Join(filepath.Dir(settingsFile), "repository")) {
		return // the default, read already
	}
	info, err := os.Lstat(repo)
	if err != nil || !info.IsDir() || !localFS(repo) {
		return
	}
	s.collectMavenRepo(repo, user)
}

// collectGradleCache reports Gradle's module cache:
// caches/modules-2/files-2.1/<group>/<artifact>/<version>/<sha1>/<file>.
// Only the version folders are listed. The location is the version folder.
func (s *scan) collectGradleCache(dir, user string) {
	for _, group := range s.subdirs(dir) {
		groupDir := filepath.Join(dir, group)
		for _, artifact := range s.subdirs(groupDir) {
			artifactDir := filepath.Join(groupDir, artifact)
			for _, version := range s.subdirs(artifactDir) {
				if s.stopped() {
					return
				}
				if nv, ok := mavenCoordinate(group, artifact, version); ok {
					s.add(Package{Ecosystem: EcosystemMaven, Name: nv.name, Version: nv.version,
						Scope: ScopeCache, Location: filepath.Join(artifactDir, version), User: user})
				}
			}
		}
	}
}
