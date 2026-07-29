package epm

// TokenType selects the privilege an allowed elevation actually launches with.
//
// It lives in internal/epm rather than internal/config because it is a domain
// concept the policy layer will also carry per-rule (a rule may prescribe a
// weaker or stronger token than the agent-wide default). internal/config
// declares matching string constants for validation instead of importing this
// package, so the lowest-level package keeps no dependency on the EPM domain;
// TestTokenTypeMatchesConfigConstants guards the two sets against drift.
type TokenType string

const (
	// TokenElevated launches with the requester's linked full-administrator
	// token — the other half of UAC's split token. This is the default and
	// the only value that grants administrative privilege to an admin user.
	// Fails for a true standard user, who has no linked token.
	TokenElevated TokenType = "elevated"

	// TokenSystem launches as LocalSystem inside the requester's session. It
	// is the only way to run something privileged on behalf of a standard
	// user, but the process runs as SYSTEM rather than as the user: no HKCU,
	// no user profile, no user network identity, and strictly more privilege
	// than an administrator's elevated token. Opt-in for exactly that reason.
	TokenSystem TokenType = "system"

	// TokenFiltered launches with the requester's own default (UAC-filtered)
	// token. It grants nothing beyond what the requester already had and
	// exists only as an escape hatch restoring pre-fix behavior.
	TokenFiltered TokenType = "filtered"
)

// Valid reports whether t is a recognised token type. TokenUserOnly (declared
// in verdict.go, for verdicts that elevate nothing at all) is included here
// rather than there so this is the one place that knows the complete set.
func (t TokenType) Valid() bool {
	switch t {
	case TokenElevated, TokenSystem, TokenFiltered, TokenUserOnly:
		return true
	}
	return false
}
