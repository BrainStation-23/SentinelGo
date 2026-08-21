// Package version classifies the build version string injected at link time,
// so the rest of the agent can tell a real release from a development build.
//
// The distinction is not cosmetic. `git describe --tags --always --dirty`
// produces strings like "v3.2.6-4-g40f52e7-dirty", and the updater's semantic
// version parser truncates at the first '-' — so that build compared, and
// reported itself, as plain "3.2.6". Three separate things went wrong at once:
//
//   - The endpoint reported a version it was not running.
//   - Four commits of uncommitted local work were invisible in that report.
//   - Worse, "v3.2.6" was not even the newest tag. HEAD sat on a branch that
//     did not contain v3.2.7 or v3.2.8, so git describe walked back to the
//     newest tag REACHABLE from HEAD. An unreachable tag silently produced an
//     older reported version than the one actually deployed — which is exactly
//     how a device reports itself as needing an update it already has, or
//     accepts one it should not.
//
// The fix is to keep git-derived metadata for development builds (it is useful
// there) while refusing to let it masquerade as a release version anywhere that
// matters: version comparison, and the release build itself.
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind classifies a version string.
type Kind string

const (
	// KindRelease is an explicit, comparable release version: vX.Y.Z, or
	// vX.Y.Z with a plain pre-release suffix such as "-rc.1".
	KindRelease Kind = "release"
	// KindDevelopment is anything else: git-describe output, a dirty tree, the
	// "dev" fallback, or an unparseable string. A development build must never
	// take part in update comparisons.
	KindDevelopment Kind = "development"
)

// DevelopmentFallback is the value config.Version takes for a plain `go build`
// with no -ldflags.
const DevelopmentFallback = "dev"

// releasePattern matches a clean release version.
//
// It deliberately does NOT match a git-describe suffix. The distinguishing
// shape is "-<commits>-g<hash>", which describePattern below identifies; a
// pre-release like "-rc.1" or "-beta2" is a legitimate release marker and is
// allowed here.
var releasePattern = regexp.MustCompile(`^[vV]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)

// describePattern matches the "<N> commits past tag <hash>" suffix that
// `git describe` appends, optionally followed by "-dirty".
var describePattern = regexp.MustCompile(`^(.*?)-(\d+)-g([0-9a-f]{4,40})(-dirty)?$`)

// Info is a classified version string.
type Info struct {
	// Raw is the string exactly as injected, always preserved for reporting.
	Raw string
	// Kind says whether this build may be treated as a release.
	Kind Kind
	// Semver is the normalised "vX.Y.Z" form when one could be derived, or "".
	//
	// For a development build this is the BASE tag git describe walked back to,
	// which is informative but must not be compared against — see the package
	// doc for why that base can be older than what is actually deployed.
	Semver string
	// PreRelease is the suffix of a release version, e.g. "rc.1". Empty for a
	// plain release.
	PreRelease string
	// Dirty reports uncommitted changes in the working tree at build time.
	Dirty bool
	// CommitsAhead is how many commits past the base tag this build sits.
	CommitsAhead int
	// Commit is the abbreviated commit hash, when git describe supplied one.
	Commit string
	// Reason explains, in one clause, why a build is not a release. Empty for
	// a release.
	Reason string
}

// Parse classifies raw. It never returns an error: an unrecognised string is a
// development build, which is the safe classification.
func Parse(raw string) Info {
	trimmed := strings.TrimSpace(raw)
	info := Info{Raw: trimmed, Kind: KindDevelopment}

	if trimmed == "" {
		info.Reason = "version string is empty"
		return info
	}
	if trimmed == DevelopmentFallback {
		info.Reason = "built without -ldflags version injection"
		return info
	}

	// Strip a trailing -dirty before anything else, so a dirty release tag is
	// recognised as "that release, but dirty" rather than as an opaque string.
	body := trimmed
	if strings.HasSuffix(body, "-dirty") {
		info.Dirty = true
		body = strings.TrimSuffix(body, "-dirty")
	}

	if m := describePattern.FindStringSubmatch(body + dirtySuffix(info.Dirty)); m != nil {
		info.Semver = normalizeSemver(m[1])
		info.CommitsAhead, _ = strconv.Atoi(m[2])
		info.Commit = m[3]
		info.Reason = fmt.Sprintf("git-describe build %d commit(s) past %s", info.CommitsAhead, m[1])
		if info.Dirty {
			info.Reason += " with uncommitted changes"
		}
		return info
	}

	m := releasePattern.FindStringSubmatch(body)
	if m == nil {
		info.Reason = "not a semantic version"
		return info
	}

	info.Semver = fmt.Sprintf("v%s.%s.%s", m[1], m[2], m[3])
	info.PreRelease = m[4]

	if info.Dirty {
		// A tagged commit built from a dirty tree is not the tag. Shipping it
		// as one is how an artifact that nobody can reproduce ends up in
		// production under a version number that says it is reproducible.
		info.Reason = "built from a working tree with uncommitted changes"
		return info
	}

	info.Kind = KindRelease
	return info
}

// dirtySuffix re-attaches the marker Parse stripped, so describePattern sees
// the original shape.
func dirtySuffix(dirty bool) string {
	if dirty {
		return "-dirty"
	}
	return ""
}

// normalizeSemver returns the vX.Y.Z form of s, or "" when s is not one.
func normalizeSemver(s string) string {
	m := releasePattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	return fmt.Sprintf("v%s.%s.%s", m[1], m[2], m[3])
}

// IsRelease reports whether this build may be treated as a released version.
func (i Info) IsRelease() bool { return i.Kind == KindRelease }

// Comparable returns the version string the updater may compare against a
// backend release, and whether comparison is allowed at all.
//
// A development build returns false. The updater must skip rather than compare,
// because the only semver a development build can offer is the base tag git
// describe reached — which, on a branch that does not contain the newest tags,
// is older than what is deployed. Comparing it would let the agent "discover"
// an update to a version it is already past, or report a downgrade as current.
func (i Info) Comparable() (string, bool) {
	if !i.IsRelease() {
		return "", false
	}
	return i.Semver, true
}

// String renders the version for human-facing output, marking a development
// build as such so it is never mistaken for a release in a log or a bug report.
func (i Info) String() string {
	if i.IsRelease() {
		return i.Raw
	}
	if i.Raw == "" {
		return "unknown (development build)"
	}
	return i.Raw + " (development build)"
}

// Validate returns an error describing why raw is not a publishable release
// version. It is what the release build gate calls; a nil error means the
// string is safe to stamp onto an artifact.
func Validate(raw string) error {
	info := Parse(raw)
	if info.IsRelease() {
		return nil
	}
	if info.Reason == "" {
		return fmt.Errorf("%q is not a release version", raw)
	}
	return fmt.Errorf("%q is not a release version: %s", raw, info.Reason)
}
