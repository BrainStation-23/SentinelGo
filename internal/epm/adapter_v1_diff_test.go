package epm

// TestV1V2Differential is the merge gate for the v1→v2 engine migration: a
// generated cross-product of v1-shaped PolicyRule values × ElevationRequest
// values, run through BOTH the preserved legacy evaluator (legacy_engine.go)
// and the v2 engine reached via NewEngine→UpgradeV1, asserting byte-identical
// (Allowed, PolicyID) for every pair. If this test fails, the corresponding
// change to UpgradeV1/matchers_identity.go does not merge — see adapter_v1.go's
// doc comment for why this class of bug is easy to introduce and hard to spot
// by inspection alone.

import (
	"fmt"
	"testing"
	"time"
)

const (
	diffMatchAppPath    = `C:\apps\tool.exe`
	diffMismatchAppPath = `C:\apps\other.exe`
	// diffGlobAppPath is deliberately a glob that MATCHES diffMatchAppPath
	// and does NOT match diffMismatchAppPath ("other.exe" does not start with
	// "to"), rather than an independent third path value. That keeps the
	// existing path-axis bit meaningful for glob rule variants too: without
	// this alignment, the "appPathGlob" rule variant would never see a
	// request that actually satisfies its glob pattern anywhere in the sweep,
	// silently never exercising glob-match agreement between the two
	// evaluators despite looking like it did.
	diffGlobAppPath = `C:\apps\to*.exe`

	diffMatchAppHash    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	diffMismatchAppHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	diffMatchPublisher    = "Contoso Inc"
	diffMismatchPublisher = "Fabrikam Inc"

	diffMatchScriptHash    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	diffMismatchScriptHash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	diffMatchArgs    = "--flag value"
	diffMismatchArgs = "--other"

	diffMatchServiceName    = "MyService"
	diffMismatchServiceName = "OtherService"

	diffMatchUserID    = `CONTOSO\alice`
	diffMismatchUserID = `CONTOSO\bob`
)

var diffRefTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// diffIdentityKinds names each shape of v1 rule to generate, selecting which
// of AppPath/AppHash/Publisher/ScriptHash are populated and how — including
// deliberately overlapping combinations that stress legacyBaseTier's
// mutual-exclusivity precedence (e.g. both ScriptHash and AppHash set: v1
// must match on ScriptHash alone). See diffApplyIdentity.
var diffIdentityKinds = []string{
	"none",             // wildcard: no identity field set at all
	"scriptHash",       // ScriptHash + AppPath set correctly (the documented pattern)
	"scriptHashNoPath", // ScriptHash set, AppPath empty — must never match (rule-authoring error)
	"appHash",
	"publisher",
	"appPathExact",
	"appPathGlob",
	"scriptHashAndAppHash",       // precedence stress: ScriptHash must win over AppHash
	"appHashAndPublisher",        // precedence stress: AppHash must win over Publisher
	"publisherAndAppPath",        // precedence stress: Publisher must win over AppPath
	"scriptHashPublisherAppPath", // precedence stress: ScriptHash must win over everything
}

func diffApplyIdentity(r *PolicyRule, kind string) {
	switch kind {
	case "none":
		// leave everything empty: wildcard
	case "scriptHash":
		r.AppPath = diffMatchAppPath
		r.ScriptHash = diffMatchScriptHash
	case "scriptHashNoPath":
		r.ScriptHash = diffMatchScriptHash
	case "appHash":
		r.AppHash = diffMatchAppHash
	case "publisher":
		r.Publisher = diffMatchPublisher
	case "appPathExact":
		r.AppPath = diffMatchAppPath
	case "appPathGlob":
		r.AppPath = diffGlobAppPath
	case "scriptHashAndAppHash":
		r.AppPath = diffMatchAppPath
		r.ScriptHash = diffMatchScriptHash
		r.AppHash = diffMatchAppHash
	case "appHashAndPublisher":
		r.AppHash = diffMatchAppHash
		r.Publisher = diffMatchPublisher
	case "publisherAndAppPath":
		r.Publisher = diffMatchPublisher
		r.AppPath = diffMatchAppPath
	case "scriptHashPublisherAppPath":
		r.AppPath = diffMatchAppPath
		r.ScriptHash = diffMatchScriptHash
		r.Publisher = diffMatchPublisher
	}
}

// diffRequestAxis is one independently-toggled dimension of the generated
// request corpus: bit set ⇒ the "matching" canonical value for that field,
// bit clear ⇒ the "mismatching" one. All seven axes are populated on every
// generated request (a real request always has every field set to
// *something*), and every one of the 2^7 combinations is exercised against
// every rule variant — including combinations irrelevant to a given rule's
// identity kind, which is exactly the point: an irrelevant field must never
// influence the outcome, and this sweep proves it for both evaluators
// identically, not just the one that happens to matter for that rule.
const diffNumAxes = 7

func diffBuildRequest(mask int) ElevationRequest {
	bit := func(n int) bool { return mask&(1<<n) != 0 }

	appPath := diffMismatchAppPath
	if bit(0) {
		appPath = diffMatchAppPath
	}
	appHash := diffMismatchAppHash
	if bit(1) {
		appHash = diffMatchAppHash
	}
	publisher := diffMismatchPublisher
	if bit(2) {
		publisher = diffMatchPublisher
	}
	scriptHash := diffMismatchScriptHash
	if bit(3) {
		scriptHash = diffMatchScriptHash
	}
	args := diffMismatchArgs
	if bit(4) {
		args = diffMatchArgs
	}
	serviceName := diffMismatchServiceName
	if bit(5) {
		serviceName = diffMatchServiceName
	}
	userID := diffMismatchUserID
	if bit(6) {
		userID = diffMatchUserID
	}

	return ElevationRequest{
		RequestID:            "req",
		UserID:               userID,
		AppPath:              appPath,
		AppHash:              appHash,
		Publisher:            publisher,
		Now:                  diffRefTime,
		ScriptPath:           `C:\apps\tool.exe`, // present whenever a script-scoped rule cares
		ScriptHash:           scriptHash,
		ActualArgs:           args,
		RequestedServiceName: serviceName,
	}
}

// diffBuildRuleSet generates every combination of identity kind × ancillary
// field presence × expiry × decision, one PolicyRule per combination. Each is
// evaluated in ISOLATION (a single-rule rule set) so the comparison isolates
// matching logic from tie-break logic; TestV1V2Differential_MultiRuleTieBreak
// covers tie-break separately.
func diffBuildRuleSet() []PolicyRule {
	var rules []PolicyRule
	id := 0
	for _, kind := range diffIdentityKinds {
		for _, allowedArgs := range []string{"", diffMatchArgs} {
			for _, allowedServiceName := range []string{"", diffMatchServiceName} {
				for _, userID := range []string{"", diffMatchUserID} {
					for _, expired := range []bool{false, true} {
						for _, decision := range []PolicyDecision{DecisionAllow, DecisionDeny} {
							r := PolicyRule{
								ID:       fmt.Sprintf("r%d", id),
								Decision: decision,
							}
							diffApplyIdentity(&r, kind)
							// AllowedArgs is only meaningful on a ScriptHash
							// rule (legacyBaseTier only consults it inside the
							// ScriptHash branch), but setting it on other
							// kinds too is a valid — if inert — extra check
							// that it has no effect when ScriptHash is unset.
							r.AllowedArgs = allowedArgs
							r.AllowedServiceName = allowedServiceName
							r.UserID = userID
							if expired {
								r.ExpiresAt = diffRefTime.Add(-1 * time.Hour)
							}
							rules = append(rules, r)
							id++
						}
					}
				}
			}
		}
	}
	return rules
}

func TestV1V2Differential(t *testing.T) {
	rules := diffBuildRuleSet()
	t.Logf("generated %d rule variants x %d request combinations = %d cases",
		len(rules), 1<<diffNumAxes, len(rules)*(1<<diffNumAxes))

	const maxReported = 25
	reported := 0

	for _, rule := range rules {
		single := []PolicyRule{rule}
		engine := NewEngine(single)

		for mask := 0; mask < (1 << diffNumAxes); mask++ {
			req := diffBuildRequest(mask)

			want := legacyEvaluate(single, req)
			got := engine.Evaluate(req)

			if want.Allowed != got.Allowed || want.PolicyID != got.PolicyID {
				reported++
				if reported <= maxReported {
					t.Errorf("rule %+v\n  request mask=%07b %+v\n  legacy = %+v\n  v2     = %+v",
						rule, mask, req, want, got)
				}
			}
		}
	}

	if reported > maxReported {
		t.Errorf("… and %d more mismatches (showing first %d)", reported-maxReported, maxReported)
	}
}

// TestV1V2Differential_MultiRuleTieBreak isolates tie-break behavior (which
// TestV1V2Differential does not exercise, since it evaluates one rule at a
// time): several rules tied on tier and priority, mixed allow/deny, must
// resolve to the SAME winner under both evaluators. This is what pins the
// deliberate decision (see betterCandidate's doc comment in engine_v2.go) to
// keep v2's tie-break identical to v1's — smaller ID wins outright, with no
// verdict-family precedence — rather than adopting a "deny beats allow"
// tie-break, which would diverge from v1 on exactly this kind of input.
func TestV1V2Differential_MultiRuleTieBreak(t *testing.T) {
	req := ElevationRequest{
		RequestID: "req",
		UserID:    diffMatchUserID,
		AppPath:   diffMatchAppPath,
		AppHash:   diffMatchAppHash,
		Now:       diffRefTime,
	}

	tests := []struct {
		name  string
		rules []PolicyRule
	}{
		{
			name: "same tier and priority, allow has smaller ID",
			rules: []PolicyRule{
				{ID: "a-allow", AppPath: diffMatchAppPath, Decision: DecisionAllow, Priority: 5},
				{ID: "z-deny", AppPath: diffMatchAppPath, Decision: DecisionDeny, Priority: 5},
			},
		},
		{
			name: "same tier and priority, deny has smaller ID",
			rules: []PolicyRule{
				{ID: "a-deny", AppPath: diffMatchAppPath, Decision: DecisionDeny, Priority: 5},
				{ID: "z-allow", AppPath: diffMatchAppPath, Decision: DecisionAllow, Priority: 5},
			},
		},
		{
			name: "hash tier beats path tier regardless of ID order",
			rules: []PolicyRule{
				{ID: "z-hash", AppHash: diffMatchAppHash, Decision: DecisionAllow},
				{ID: "a-path", AppPath: diffMatchAppPath, Decision: DecisionDeny},
			},
		},
		{
			name: "higher priority wins within the same tier",
			rules: []PolicyRule{
				{ID: "a-low", AppPath: diffMatchAppPath, Decision: DecisionAllow, Priority: 1},
				{ID: "b-high", AppPath: diffMatchAppPath, Decision: DecisionDeny, Priority: 10},
			},
		},
		{
			name: "five-way tie resolves to the smallest ID",
			rules: []PolicyRule{
				{ID: "e", AppPath: diffMatchAppPath, Decision: DecisionDeny},
				{ID: "c", AppPath: diffMatchAppPath, Decision: DecisionAllow},
				{ID: "a", AppPath: diffMatchAppPath, Decision: DecisionDeny},
				{ID: "d", AppPath: diffMatchAppPath, Decision: DecisionAllow},
				{ID: "b", AppPath: diffMatchAppPath, Decision: DecisionDeny},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := legacyEvaluate(tc.rules, req)
			got := NewEngine(tc.rules).Evaluate(req)
			if want.Allowed != got.Allowed || want.PolicyID != got.PolicyID {
				t.Errorf("legacy = %+v, v2 = %+v", want, got)
			}
		})
	}
}
