package epm

import (
	"runtime"
	"strings"
	"time"
)

// This file implements every Matcher sourced directly from EvalInput.Request
// (application identity, invocation, and principal — no ContextSnapshot
// involved), plus allBuiltinMatchers, which assembles the complete registry
// returned by DefaultMatchers. See matchers_context.go for the
// ContextSnapshot-sourced matchers (posture, network, org, time, platform).
//
// MaxAge is 0 for every matcher in this file: each reads a value supplied
// fresh on the current request (or, for CondUser/CondUserGroup, resolved by
// the transport at accept time), so there is no background-collected fact
// that can go stale.

// normalizeSeparators normalizes '\' to '/' so glob and exact path comparison
// (applyOperator, compile.go) behave identically regardless of host GOOS —
// the same normalization legacyPathMatches applies, under a fresh name since
// legacy_engine.go's copy is intentionally frozen for the differential test.
func normalizeSeparators(s string) string {
	return strings.ReplaceAll(s, `\`, "/")
}

func allBuiltinMatchers() []Matcher {
	return []Matcher{
		// Application identity.
		pathMatcher{}, fileNameMatcher{}, sha256Matcher{}, sha1Matcher{},
		scriptSHA256Matcher{}, publisherMatcher{}, signedMatcher{},
		productNameMatcher{}, msiProductCodeMatcher{}, bundleIDMatcher{}, packageNameMatcher{},

		// Invocation.
		commandLineMatcher{}, argsMatcher{}, serviceNameMatcher{},
		parentProcessMatcher{}, childProcessMatcher{},

		// Principal.
		userMatcher{}, userSIDMatcher{}, userGroupMatcher{},

		// Context-sourced (matchers_context.go).
		deviceGroupMatcher{}, orgMatcher{}, departmentMatcher{},
		domainJoinedMatcher{}, entraJoinedMatcher{},
		diskEncryptionMatcher{}, secureBootMatcher{}, firewallMatcher{},
		antivirusMatcher{}, complianceMatcher{},
		networkTypeMatcher{}, vpnActiveMatcher{}, corporateNetworkMatcher{},
		businessHoursMatcher{}, dayOfWeekMatcher{},
		osTypeMatcher{}, osVersionMatcher{},
	}
}

// --- Application identity ---

// pathMatcher reproduces v1's exact glob semantics (pathMatches in the
// preserved legacy_engine.go): '\' normalized to '/' on both sides so
// path.Match's glob behavior is GOOS-independent, plus a case-insensitive
// exact compare on Windows (a v1 bug fix — case-sensitive exact matching meant
// an author's own path casing had to exactly match the filesystem's, which
// Windows itself does not require). applyOperator (compile.go) does the exact
// glob/eq comparison; this Extract only has to hand back the normalized
// actual path.
//
// Always reports known=true, even for an empty AppPath. v1's path comparison
// (legacyBaseTier) is an unconditional string/glob compare with no verdict-
// family awareness — a rule requiring a path that the request doesn't supply
// simply fails to match, for an allow rule and a deny rule alike. Reporting
// unknown=false here instead would route an empty AppPath through the
// verdict-family Unknown default (compile.go's evalTree), which — for a
// deny-family rule — treats Unknown as "matches," the opposite of v1's
// unconditional non-match. See userMatcher, argsMatcher, serviceNameMatcher,
// publisherMatcher, sha256Matcher, and scriptSHA256Matcher for the same
// reasoning applied to the rest of v1's unconditional comparisons.
type pathMatcher struct{}

func (pathMatcher) Kind() ConditionKind   { return CondPath }
func (pathMatcher) Weight() int           { return WeightPathExact }
func (pathMatcher) MaxAge() time.Duration { return 0 }
func (pathMatcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{normalizeSeparators(in.Request.AppPath)}, true
}

// fileNameMatcher matches on the final path segment only (e.g. "tool.exe"),
// letting a rule target an executable name regardless of install location. No
// v1 equivalent; purely additive. Always known, for the same reason as
// pathMatcher — it is derived from the same always-present request field.
type fileNameMatcher struct{}

func (fileNameMatcher) Kind() ConditionKind   { return CondFileName }
func (fileNameMatcher) Weight() int           { return WeightFileName }
func (fileNameMatcher) MaxAge() time.Duration { return 0 }
func (fileNameMatcher) Extract(in *EvalInput) ([]string, bool) {
	norm := normalizeSeparators(in.Request.AppPath)
	if i := strings.LastIndexByte(norm, '/'); i >= 0 {
		norm = norm[i+1:]
	}
	return []string{norm}, true
}

// sha256Matcher is always known — see pathMatcher's doc comment. In practice
// AppHash is always populated by the time a request reaches evaluation
// (computeFileHashFn's error path in pipe_windows.go/socket_linux.go is a hard
// failure that never reaches Engine.Evaluate), so this only matters for
// synthetic/test requests, but the semantics must still be exact for those.
//
// Deliberately does NOT lowercase the extracted value. v1's comparison
// (legacyBaseTier: `rule.AppHash == req.AppHash`) is a raw, case-sensitive
// string equality with no normalization on either side. Folding only the
// extracted side here while leaving the leaf's authored value (built by
// UpgradeV1 from the same raw r.AppHash) unfolded would make the two sides
// disagree whenever a hash happens to be authored or reported in a
// non-lowercase form — a real divergence risk, not a hypothetical one, since
// nothing in this package enforces the "lowercase hex" convention the
// PolicyRule doc comment merely documents.
type sha256Matcher struct{}

func (sha256Matcher) Kind() ConditionKind   { return CondSHA256 }
func (sha256Matcher) Weight() int           { return WeightHash }
func (sha256Matcher) MaxAge() time.Duration { return 0 }
func (sha256Matcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{in.Request.AppHash}, true
}

// sha1Matcher has no current producer — internal/hashutil only computes
// SHA-256 — so this reports unknown until a SHA-1 collector exists. Wired now
// so an authored sha1 rule compiles and fails closed rather than being
// rejected outright.
type sha1Matcher struct{}

func (sha1Matcher) Kind() ConditionKind   { return CondSHA1 }
func (sha1Matcher) Weight() int           { return WeightHashWeak }
func (sha1Matcher) MaxAge() time.Duration { return 0 }
func (sha1Matcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.SHA1 == "" {
		return nil, false
	}
	return []string{strings.ToLower(in.Request.SHA1)}, true
}

// scriptSHA256Matcher is compound in v1 (implicitly requires AppPath to also
// match — see UpgradeV1's mirroring of legacyBaseTier's ScriptHash branch).
// Here it is a single leaf; the AND with CondPath is made explicit by the
// adapter, not hidden inside this matcher, so the condition tree shows the
// real dependency instead of a matcher with surprising side constraints.
// Always known — v1's `rule.ScriptHash != req.ScriptHash` is an unconditional,
// case-sensitive raw compare; see pathMatcher and sha256Matcher's doc comment
// on why this does not lowercase either.
type scriptSHA256Matcher struct{}

func (scriptSHA256Matcher) Kind() ConditionKind   { return CondScriptSHA256 }
func (scriptSHA256Matcher) Weight() int           { return WeightHash }
func (scriptSHA256Matcher) MaxAge() time.Duration { return 0 }
func (scriptSHA256Matcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{in.Request.ScriptHash}, true
}

// publisherMatcher compares the extracted publisher string exactly, always
// known — v1's `rule.Publisher != req.Publisher` is an unconditional compare;
// see pathMatcher. This is deliberately distinct from signedMatcher below: an
// empty Publisher here simply fails to equal any specific authored publisher
// name (matching v1 exactly), whereas signedMatcher asks a different
// question — "is this signed at all" — for which an empty Publisher is
// genuinely ambiguous and must be Unknown, not a confident "no."
type publisherMatcher struct{}

func (publisherMatcher) Kind() ConditionKind   { return CondPublisher }
func (publisherMatcher) Weight() int           { return WeightPublisher }
func (publisherMatcher) MaxAge() time.Duration { return 0 }
func (publisherMatcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{in.Request.Publisher}, true
}

// signedMatcher answers "is this binary signed at all," typically used with
// OpIsFalse to deny/prompt on unsigned binaries. An empty Publisher is
// genuinely ambiguous — codesign_windows.go/codesign_linux.go/codesign_darwin.go
// all swallow verification errors (`publisher, _ := verifyAuthenticodeFn(...)`),
// so "" could mean "definitely unsigned" or "verification failed for an
// unrelated reason." Extract reports unknown in that case rather than
// guessing, which is why a bare "block unsigned" rule needs OnUnknown="match"
// on a deny-family verdict to fail closed — documented in
// docs/EPM-Policy-Bundle-Format.md (Phase 3).
type signedMatcher struct{}

func (signedMatcher) Kind() ConditionKind   { return CondSigned }
func (signedMatcher) Weight() int           { return WeightPublisher }
func (signedMatcher) MaxAge() time.Duration { return 0 }
func (signedMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.Publisher == "" {
		return nil, false
	}
	return []string{"true"}, true
}

type productNameMatcher struct{}

func (productNameMatcher) Kind() ConditionKind   { return CondProductName }
func (productNameMatcher) Weight() int           { return WeightProductName }
func (productNameMatcher) MaxAge() time.Duration { return 0 }
func (productNameMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.ProductName == "" {
		return nil, false
	}
	return []string{in.Request.ProductName}, true
}

type msiProductCodeMatcher struct{}

func (msiProductCodeMatcher) Kind() ConditionKind   { return CondMSIProductCode }
func (msiProductCodeMatcher) Weight() int           { return WeightHash }
func (msiProductCodeMatcher) MaxAge() time.Duration { return 0 }
func (msiProductCodeMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.MSIProductCode == "" {
		return nil, false
	}
	return []string{strings.ToUpper(in.Request.MSIProductCode)}, true
}

type bundleIDMatcher struct{}

func (bundleIDMatcher) Kind() ConditionKind   { return CondBundleID }
func (bundleIDMatcher) Weight() int           { return WeightBundleID }
func (bundleIDMatcher) MaxAge() time.Duration { return 0 }
func (bundleIDMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.BundleID == "" {
		return nil, false
	}
	return []string{in.Request.BundleID}, true
}

type packageNameMatcher struct{}

func (packageNameMatcher) Kind() ConditionKind   { return CondPackageName }
func (packageNameMatcher) Weight() int           { return WeightPackage }
func (packageNameMatcher) MaxAge() time.Duration { return 0 }
func (packageNameMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.PackageName == "" {
		return nil, false
	}
	return []string{in.Request.PackageName}, true
}

// --- Invocation ---

type commandLineMatcher struct{}

func (commandLineMatcher) Kind() ConditionKind   { return CondCommandLine }
func (commandLineMatcher) Weight() int           { return WeightArgsExact }
func (commandLineMatcher) MaxAge() time.Duration { return 0 }
func (commandLineMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.CommandLine == "" {
		return nil, false
	}
	return []string{in.Request.CommandLine}, true
}

// argsMatcher is always known — v1's compound ScriptHash match compares
// req.ActualArgs against rule.AllowedArgs unconditionally when AllowedArgs is
// set (legacyBaseTier); see pathMatcher.
type argsMatcher struct{}

func (argsMatcher) Kind() ConditionKind   { return CondArgs }
func (argsMatcher) Weight() int           { return WeightArgsExact }
func (argsMatcher) MaxAge() time.Duration { return 0 }
func (argsMatcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{strings.TrimSpace(in.Request.ActualArgs)}, true
}

// serviceNameMatcher reproduces v1's veto-only semantics (legacyServiceNameMatches)
// by being always known rather than reporting Unknown when no service name was
// extracted — v1's veto is unconditional (it applies the same way to an allow
// rule and a deny rule alike), so it must resolve as a plain non-match
// (TriFalse), not as Unknown routed through the verdict-family default: for a
// DENY-family rule, an Unknown result would resolve to "matches" (fail
// closed), which is the opposite of v1's unconditional "no service name
// extracted ⇒ this rule does not apply" veto. See pathMatcher for the general
// reasoning and matchers_identity_test.go's deny-rule case for the regression
// this specifically guards.
//
// Case folding mirrors v1 exactly: fold on Windows, exact elsewhere, because
// Windows service names are case-insensitive and svcparse's extraction
// reflects whatever case appeared on the command line. UpgradeV1 folds the
// rule's authored AllowedServiceName the same way at adapt time (GOOS is
// fixed for the lifetime of the running agent process, so folding once at
// adapt time and once per Extract call agree).
type serviceNameMatcher struct{}

func (serviceNameMatcher) Kind() ConditionKind   { return CondServiceName }
func (serviceNameMatcher) Weight() int           { return WeightServiceName }
func (serviceNameMatcher) MaxAge() time.Duration { return 0 }
func (serviceNameMatcher) Extract(in *EvalInput) ([]string, bool) {
	name := in.Request.RequestedServiceName
	if runtime.GOOS == "windows" {
		name = strings.ToLower(name)
	}
	return []string{name}, true
}

// parentProcessMatcher has no current producer — no transport supplies
// ElevationRequestV2.ParentProcess yet (that lands with process-context work
// in a later phase) — so it reports unknown until then.
type parentProcessMatcher struct{}

func (parentProcessMatcher) Kind() ConditionKind   { return CondParentProcess }
func (parentProcessMatcher) Weight() int           { return WeightParentChild }
func (parentProcessMatcher) MaxAge() time.Duration { return 0 }
func (parentProcessMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.ParentProcess == "" {
		return nil, false
	}
	return []string{normalizeSeparators(in.Request.ParentProcess)}, true
}

// childProcessMatcher: see parentProcessMatcher — no current producer.
type childProcessMatcher struct{}

func (childProcessMatcher) Kind() ConditionKind   { return CondChildProcess }
func (childProcessMatcher) Weight() int           { return WeightParentChild }
func (childProcessMatcher) MaxAge() time.Duration { return 0 }
func (childProcessMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Request.ChildProcess == "" {
		return nil, false
	}
	return []string{normalizeSeparators(in.Request.ChildProcess)}, true
}

// --- Principal ---

// userMatcher matches on the same UserID field v1's outer scoping check used
// (rule.UserID != "" && rule.UserID != req.UserID). Unlike v1, which applied
// this as an unconditional pre-filter outside the tier system, v2 folds it
// into the tree as an ordinary AND leaf (see UpgradeV1) — same effect, one
// fewer special case in the engine. Comparison is exact and case-sensitive,
// matching v1's `!=` exactly; case-insensitive Windows account matching is a
// deliberate non-goal here (same gap v1 had — CondUserSID exists precisely so
// an author who needs case/format-independent identity can key on the SID
// instead). Always known, for the same unconditional-compare reason as
// pathMatcher: v1's UserID scoping check applies identically whether the
// rule allows or denies.
type userMatcher struct{}

func (userMatcher) Kind() ConditionKind   { return CondUser }
func (userMatcher) Weight() int           { return WeightUser }
func (userMatcher) MaxAge() time.Duration { return 0 }
func (userMatcher) Extract(in *EvalInput) ([]string, bool) {
	return []string{in.Request.UserID}, true
}

// userSIDMatcher has no current producer — the Windows transport resolves a
// "DOMAIN\User" display string (userIDForToken), not a SID string — so this
// reports unknown until that resolution is extended.
type userSIDMatcher struct{}

func (userSIDMatcher) Kind() ConditionKind   { return CondUserSID }
func (userSIDMatcher) Weight() int           { return WeightUser }
func (userSIDMatcher) MaxAge() time.Duration { return 0 }
func (userSIDMatcher) Extract(*EvalInput) ([]string, bool) {
	return nil, false
}

// userGroupMatcher has no current producer — group membership resolution is
// Phase 2's Identifier.Groups(peer) — so this reports unknown until that
// lands. Uses OpIn semantics naturally: Values lists the groups a rule wants
// to match against membership in ANY of them.
type userGroupMatcher struct{}

func (userGroupMatcher) Kind() ConditionKind   { return CondUserGroup }
func (userGroupMatcher) Weight() int           { return WeightUserGroup }
func (userGroupMatcher) MaxAge() time.Duration { return 0 }
func (userGroupMatcher) Extract(in *EvalInput) ([]string, bool) {
	if len(in.Request.UserGroups) == 0 {
		return nil, false
	}
	return in.Request.UserGroups, true
}
