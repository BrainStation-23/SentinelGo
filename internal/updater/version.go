package updater

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"sentinelgo/internal/buildflavor"
	"sentinelgo/internal/sanitize"
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
	actionSwitch                        // the same version in the other build (#548)
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

// decideRelease is decideUpdate for a release in build flavor (#548). A
// release in another build than this binary's is installed at the same
// version too: that is how the server moves a device between the full and
// the read-only build, either way. An older one still needs allow_downgrade.
func decideRelease(candidate, current string, allowDowngrade bool, flavor string) (updateAction, error) {
	action, err := decideUpdate(candidate, current, allowDowngrade)
	if err == nil && action == actionNone && flavor != buildflavor.Flavor && sameVersion(candidate, current) {
		return actionSwitch, nil
	}
	return action, err
}

// releaseFlavor is the build latest is: its flavor column, or this binary's
// when the server doesn't send one. It refuses a flavor this agent doesn't
// know and an asset whose name is another build's: installing the wrong
// build would only be undone by the next check, again and again.
func releaseFlavor(latest *LatestRelease) (string, error) {
	flavor := latest.Flavor
	if flavor == "" {
		flavor = buildflavor.Flavor
	}
	if flavor != buildflavor.FlavorFull && flavor != buildflavor.FlavorReadOnly {
		return "", fmt.Errorf("refusing to update to %s: unknown build flavor %q", sanitize.ForLog(latest.Version), sanitize.ForLog(flavor))
	}
	name := latest.AssetName
	if name == "" {
		name = path.Base(latest.AssetPath)
	}
	if strings.HasPrefix(name, "sentinelgo-readonly-") != (flavor == buildflavor.FlavorReadOnly) {
		return "", fmt.Errorf("refusing to update to %s: asset %s isn't the %s build", sanitize.ForLog(latest.Version), sanitize.ForLog(name), flavor)
	}
	return flavor, nil
}

// sameVersion reports whether a and b name the same release; unparseable
// versions compare as strings.
func sameVersion(a, b string) bool {
	x, errA := parseSemver(a)
	y, errB := parseSemver(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return x.compare(y) == 0
}
