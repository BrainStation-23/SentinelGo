package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// semver is a parsed major.minor.patch version. Pre-release and build metadata
// (anything after '-' or '+') are ignored for comparison purposes.
type semver struct {
	major, minor, patch int
}

// parseSemver parses a version string of the form "vX.Y.Z" or "X.Y.Z".
// A leading 'v' is optional. Missing minor/patch components default to 0.
func parseSemver(s string) (semver, error) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	// Strip pre-release / build metadata.
	if i := strings.IndexAny(v, "-+"); i != -1 {
		v = v[:i]
	}

	if v == "" {
		return semver{}, fmt.Errorf("empty version")
	}

	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return semver{}, fmt.Errorf("invalid version %q: too many components", s)
	}

	nums := make([]int, 3)
	for i := 0; i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return semver{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		if n < 0 {
			return semver{}, fmt.Errorf("invalid version %q: negative component", s)
		}
		nums[i] = n
	}

	return semver{major: nums[0], minor: nums[1], patch: nums[2]}, nil
}

// compare returns -1 if a < b, 0 if equal, +1 if a > b.
func (a semver) compare(b semver) int {
	switch {
	case a.major != b.major:
		return cmpInt(a.major, b.major)
	case a.minor != b.minor:
		return cmpInt(a.minor, b.minor)
	default:
		return cmpInt(a.patch, b.patch)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// compareVersions returns candidate.compare(current). Both must be valid
// semantic versions; an error is returned when either cannot be parsed (e.g.
// a "dev" build), in which case the caller should skip the update rather than
// apply an unverifiable change.
func compareVersions(candidate, current string) (int, error) {
	c, err := parseSemver(candidate)
	if err != nil {
		return 0, fmt.Errorf("candidate version: %w", err)
	}
	cur, err := parseSemver(current)
	if err != nil {
		return 0, fmt.Errorf("current version: %w", err)
	}
	return c.compare(cur), nil
}

// isNewerVersion reports whether candidate is a strictly newer release than
// current (see compareVersions for errors).
func isNewerVersion(candidate, current string) (bool, error) {
	c, err := compareVersions(candidate, current)
	return c > 0, err
}

// updateAction is what CheckAndApply does with the server's latest release.
type updateAction int

const (
	actionNone      updateAction = iota // equal, or older without approval
	actionUpgrade                       // strictly newer
	actionDowngrade                     // older, and the server set allow_downgrade
)

// decideUpdate picks the action for a release. Downgrades happen only when
// the server explicitly asks (allow_downgrade, set during an admin-initiated,
// audited rollback); otherwise an older or equal tag never triggers an
// update, which blocks downgrade attacks. Either way the release must still
// pass the SHA-256 and ed25519 signature checks.
func decideUpdate(candidate, current string, allowDowngrade bool) (updateAction, error) {
	c, err := compareVersions(candidate, current)
	switch {
	case err != nil:
		return actionNone, err
	case c > 0:
		return actionUpgrade, nil
	case c < 0 && allowDowngrade:
		return actionDowngrade, nil
	default:
		return actionNone, nil
	}
}
