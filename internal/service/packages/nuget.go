package packages

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"strings"
)

// parseProjectAssets reads obj/project.assets.json, the resolved graph
// `dotnet restore` writes: its "libraries" map has "<id>/<version>" keys,
// with type "package" for NuGet packages ("project" for project
// references, which aren't).
func parseProjectAssets(data []byte) []nameVersion {
	var assets struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil
	}
	var out []nameVersion
	for key, lib := range assets.Libraries {
		if lib.Type != "package" {
			continue
		}
		id, version, ok := strings.Cut(key, "/")
		if v, vok := nugetVersion(version); ok && vok && nugetID(id) {
			out = append(out, nameVersion{id, v})
		}
	}
	return out
}

// parseNuGetLock reads packages.lock.json (RestorePackagesWithLockFile):
// dependencies.<target framework>.<id>.resolved. Project references have no
// resolved version.
func parseNuGetLock(data []byte) []nameVersion {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []nameVersion
	for _, deps := range lock.Dependencies {
		for id, d := range deps {
			if strings.EqualFold(d.Type, "project") {
				continue
			}
			if v, ok := nugetVersion(d.Resolved); ok && nugetID(id) {
				out = append(out, nameVersion{id, v})
			}
		}
	}
	return out
}

// parsePackagesConfig reads a legacy .NET Framework packages.config:
// <packages><package id="…" version="…" /></packages>.
func parsePackagesConfig(data []byte) []nameVersion {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var out []nameVersion
	for {
		tok, err := dec.Token()
		if err != nil { // io.EOF or a malformed document
			return out
		}
		el, ok := tok.(xml.StartElement)
		if !ok || el.Name.Local != "package" {
			continue
		}
		var id, version string
		for _, a := range el.Attr {
			switch a.Name.Local {
			case "id":
				id = strings.TrimSpace(a.Value)
			case "version":
				version = a.Value
			}
		}
		if v, ok := nugetVersion(version); ok && nugetID(id) {
			out = append(out, nameVersion{id, v})
		}
	}
}

// nugetVersion accepts a NuGet version ("13.0.3", "1.0.0-beta.2",
// "4.5.0+build"); version ranges ("[1.0, )") and floating versions ("1.*")
// aren't one installed version.
func nugetVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, " ,()[]*/\\:") {
		return "", false
	}
	return v, true
}

// nugetID accepts a package id (letters, digits, ".", "-", "_").
func nugetID(id string) bool { return nameChars(id, ".-_") }

// collectNuGetTools reports .NET global tools (dotnet tool install -g):
// <store>/<id>/<version>/, with the id in lower case. The location is the
// version folder.
func (s *scan) collectNuGetTools(store, user string) {
	s.collectIDVersionDirs(store, user, ScopeGlobal)
}

// collectNuGetCache reports the NuGet global packages folder
// (~/.nuget/packages/<id>/<version>/): every version a restore downloaded.
func (s *scan) collectNuGetCache(dir, user string) {
	s.collectIDVersionDirs(dir, user, ScopeCache)
}

func (s *scan) collectIDVersionDirs(dir, user, scope string) {
	for _, id := range s.subdirs(dir) {
		if !nugetID(id) {
			continue
		}
		idDir := filepath.Join(dir, id)
		for _, version := range s.subdirs(idDir) {
			if s.stopped() {
				return
			}
			if v, ok := nugetVersion(version); ok {
				s.add(Package{Ecosystem: EcosystemNuGet, Name: id, Version: v,
					Scope: scope, Location: filepath.Join(idDir, version), User: user})
			}
		}
	}
}
