//go:build linux

package devicectx

import (
	"strings"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/osinfo/shared"
)

// collectJoinReal shells out to `realm list` — the standard front-end for
// both sssd and winbind AD-join configurations on Linux — a single,
// deliberately minimal check (see join.go's doc comment for why this isn't
// the fuller realm -> adcli -> krb5.keytab/sssd.conf fallback chain the
// original design sketch considered).
//
// EntraJoined is always reported Unknown on Linux, not false: this package
// has no Entra/Azure AD Linux collector at all (hybrid Entra join on Linux
// is a rare, unsupported-here configuration), and reporting a value this
// code never actually checked would be a fabrication — Unknown correctly
// tells a rule author "not evaluated on this platform" rather than
// asserting a fact nobody verified. See matchers_context.go's
// entraJoinedMatcher: TriUnknown here makes CondEntraJoined report Unknown
// regardless of the "join" source's overall health.
func collectJoinReal() joinResult {
	out, exitCode, err := shared.RunCommandOutput("realm", "list")
	if err != nil {
		return joinResult{ok: false, errMsg: err.Error(), entraJoined: epm.TriUnknown}
	}
	if exitCode != 0 {
		// realm not installed, not configured, or the machine simply is not
		// joined to anything — realm list exits non-zero with no realms
		// configured on some distros. Either way this is a known, negative
		// fact, not a collection failure: mark the source healthy with
		// DomainJoined=false rather than Unknown.
		return joinResult{ok: true, domainJoined: epm.TriFalse, entraJoined: epm.TriUnknown}
	}

	domainName := parseRealmDomainName(out)
	joined := epm.TriFalse
	if strings.TrimSpace(out) != "" {
		joined = epm.TriTrue
	}
	return joinResult{ok: true, domainJoined: joined, domainName: domainName, entraJoined: epm.TriUnknown}
}

func parseRealmDomainName(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "domain-name:"); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}
