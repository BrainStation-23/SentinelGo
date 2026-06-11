package updater

import (
	"fmt"
	"net/url"
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

// isNewerVersion reports whether candidate is a strictly newer release than
// current. Both must be valid semantic versions; an error is returned when
// either cannot be parsed (e.g. a "dev" build), in which case the caller should
// skip the update rather than apply an unverifiable change. This blocks
// downgrade attacks: an older or equal tag never triggers an update.
func isNewerVersion(candidate, current string) (bool, error) {
	c, err := parseSemver(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate version: %w", err)
	}
	cur, err := parseSemver(current)
	if err != nil {
		return false, fmt.Errorf("current version: %w", err)
	}
	return c.compare(cur) > 0, nil
}

// allowedDownloadHosts is the set of hosts the updater will download release
// assets from. GitHub serves release binaries from github.com and redirects to
// *.githubusercontent.com object storage.
var allowedDownloadHosts = []string{
	"github.com",
	"api.github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

// validateGitHubURL ensures rawURL is an HTTPS URL pointing at a trusted GitHub
// host before the updater downloads from it. This is a defense-in-depth check;
// it is NOT a substitute for the (deferred) cryptographic signature verification
// that establishes binary authenticity.
func validateGitHubURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	host := u.Hostname()
	for _, allowed := range allowedDownloadHosts {
		if host == allowed || strings.HasSuffix(host, ".githubusercontent.com") {
			return nil
		}
	}
	return fmt.Errorf("host %q is not an allowed GitHub host", host)
}
