package devicectx

import "sentinelgo/internal/epm"

// joinResult is what a platform's collectJoinReal produces for
// provider.go's collectPosture to fold into the "join" source of the shared
// snapshot (see matchers_context.go's domainJoinedMatcher/entraJoinedMatcher,
// which key off ctx.Sources["join"]).
//
// Every platform implementation here is deliberately a single subprocess (or
// registry) check rather than the fuller multi-fallback chain the original
// design sketch considered (Windows: NetGetJoinInformation + a
// CloudDomainJoin registry read; Linux: realm -> adcli -> krb5.keytab/sssd.conf
// fallback chain) — a documented, accepted scope reduction given the size of
// the remaining work in this redesign. ok=false (with errMsg set) leaves
// DomainJoined/EntraJoined at TriUnknown, which is the fail-closed default
// for any allow-family rule conditioning on them, so a detector that cannot
// run at all (missing tool, permission denied) degrades safely rather than
// silently reporting "not joined".
type joinResult struct {
	domainJoined epm.Tri
	domainName   string
	entraJoined  epm.Tri
	tenantID     string

	ok     bool
	errMsg string
}
