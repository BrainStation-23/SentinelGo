package packages

import (
	"encoding/json"
	"strings"
)

// parsePackageResolved reads SwiftPM's Package.resolved: version 1
// (object.pins[].repositoryURL) and versions 2 and 3 (pins[].location).
// The name is the repository URL (OSV's SwiftURL; the server normalises
// it). Pins to a branch or a revision only have no release version, and
// local packages aren't in a registry: both are skipped.
func parsePackageResolved(data []byte) []nameVersion {
	type state struct {
		Version *string `json:"version"`
	}
	type pin struct {
		RepositoryURL string `json:"repositoryURL"`
		Location      string `json:"location"`
		Kind          string `json:"kind"`
		State         state  `json:"state"`
	}
	var f struct {
		Object struct {
			Pins []pin `json:"pins"`
		} `json:"object"`
		Pins []pin `json:"pins"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil
	}
	var out []nameVersion
	for _, p := range append(f.Object.Pins, f.Pins...) {
		url := strings.TrimSpace(firstNonEmpty(p.RepositoryURL, p.Location))
		if p.State.Version == nil || strings.HasPrefix(p.Kind, "local") || !swiftRepoURL(url) {
			continue
		}
		if v, ok := cargoVersion(*p.State.Version); ok {
			out = append(out, nameVersion{url, v})
		}
	}
	return out
}

// swiftRepoURL accepts a remote repository: a URL with a scheme
// (https://host/owner/repo) or an scp-style git address (git@host:owner/repo).
func swiftRepoURL(u string) bool {
	if u == "" || strings.ContainsAny(u, " \t\n") {
		return false
	}
	if scheme, rest, ok := strings.Cut(u, "://"); ok {
		return scheme != "file" && strings.Contains(rest, "/")
	}
	at, colon := strings.Index(u, "@"), strings.Index(u, ":")
	return at > 0 && colon > at
}
