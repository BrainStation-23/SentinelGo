//go:build darwin

package devicectx

import (
	"strings"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/osinfo/shared"
)

// collectJoinReal shells out to `dsconfigad -show`, the standard way to
// inspect Active Directory binding state on macOS — a single, deliberately
// minimal check (see join.go's doc comment). An unbound Mac makes the
// command exit non-zero with no "Active Directory Domain" line, which this
// treats as a known, healthy "not domain joined" rather than a failure.
//
// EntraJoined is always reported Unknown: this package has no macOS
// Entra/Azure AD collector (Company Portal / device-based Conditional
// Access state is not exposed via any documented CLI), so, as on Linux,
// reporting anything other than Unknown here would be asserting a fact this
// code never checked.
func collectJoinReal() joinResult {
	out, _, err := shared.RunCommandOutput("dsconfigad", "-show")
	if err != nil {
		return joinResult{ok: false, errMsg: err.Error(), entraJoined: epm.TriUnknown}
	}

	domainName := parseDsconfigadDomain(out)
	joined := epm.TriFalse
	if domainName != "" {
		joined = epm.TriTrue
	}
	return joinResult{ok: true, domainJoined: joined, domainName: domainName, entraJoined: epm.TriUnknown}
}

func parseDsconfigadDomain(out string) string {
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if strings.EqualFold(key, "Active Directory Domain") {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
