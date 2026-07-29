package epm

import (
	"runtime"
	"strings"
)

// UpgradeV1 lowers a legacy PolicyRule into its v2 RuleV2 representation. It
// is a pure function, so identical code runs whether the rule was loaded
// straight from the SQLite epm_policies table (see NewEngine) or arrived as a
// v1-shaped policy-sync payload from a backend that has not adopted the v2
// bundle format — both paths reach the same v2 engine through the same
// upgrade.
//
// The switch below deliberately mirrors legacyBaseTier's if-chain exactly,
// including its mutual exclusivity: in v1, a rule with both AppHash and
// AppPath set matches on the hash ALONE — AppPath is silently ignored.
// Emitting an AND of both here would make such a rule require BOTH to match,
// which is stricter than v1 and would silently stop it from matching
// requests v1 used to allow (or deny) for it. This is the single highest
// back-compat risk in the whole engine rewrite, which is why
// TestV1V2Differential (adapter_v1_diff_test.go) exists as a merge gate: it
// is not suficient to reason about this switch by inspection, it has to be
// checked against the preserved legacy_engine.go algorithm across a large
// generated corpus.
//
// A second, easy-to-miss risk this function specifically avoids: several of
// v1's field comparisons (AppHash, Publisher, AppPath, ScriptHash,
// AllowedArgs, AllowedServiceName, UserID) are UNCONDITIONAL raw compares —
// they apply the same way regardless of whether the rule allows or denies.
// The v2 engine's default Unknown-handling, by contrast, is verdict-family
// aware (an allow-family rule does not match on Unknown; a deny-family rule
// does). If any of these leaves reported Unknown when its target request
// field was empty, a v1 DENY rule with (say) AllowedServiceName set would
// start matching unconditionally whenever no service name was extracted —
// exactly backwards from v1's unconditional veto. The matchers this function
// emits leaves for (pathMatcher, sha256Matcher, publisherMatcher,
// scriptSHA256Matcher, argsMatcher, serviceNameMatcher, userMatcher) are all
// deliberately "always known" for this reason — see each one's doc comment in
// matchers_identity.go.
func UpgradeV1(r PolicyRule) RuleV2 {
	var target []*Condition
	switch {
	case r.ScriptHash != "":
		// Compound: the interpreter path AND the script's own hash, plus an
		// optional exact-args constraint.
		var pathLeaf *Condition
		if r.AppPath == "" {
			// legacyBaseTier: a ScriptHash rule with no AppPath is a
			// rule-authoring error and fails closed UNCONDITIONALLY —
			// "return tierNone" happens before pathMatches is even called, so
			// it never matches regardless of req.AppPath, including an empty
			// one. A leaf(CondPath, OpEquals, "") would NOT reproduce that:
			// pathMatcher is always-known (see its doc comment), so comparing
			// "" == "" would be TRUE for a synthetic request that also has an
			// empty AppPath — a real divergence the differential test can and
			// does construct. OpIn with no Values can never be satisfied by
			// any extracted value (applyOperator's OpIn case loops over an
			// empty Values and always returns false), which reproduces
			// "impossible to match" directly instead of relying on an
			// empty-string coincidence.
			pathLeaf = &Condition{Kind: CondPath, Operator: OpIn}
		} else {
			pathLeaf = leaf(CondPath, opForPattern(r.AppPath), normalizeSeparators(r.AppPath))
		}
		target = append(target, pathLeaf, leaf(CondScriptSHA256, OpEquals, r.ScriptHash))
		if r.AllowedArgs != "" {
			target = append(target, leaf(CondArgs, OpEquals, r.AllowedArgs))
		}
	case r.AppHash != "":
		target = append(target, leaf(CondSHA256, OpEquals, r.AppHash))
	case r.Publisher != "":
		target = append(target, leaf(CondPublisher, OpEquals, r.Publisher))
	case r.AppPath != "":
		target = append(target, leaf(CondPath, opForPattern(r.AppPath), normalizeSeparators(r.AppPath)))
	default:
		// Wildcard: no application-identity condition at all, exactly v1's
		// tierWildcard rule ("allow this user to elevate anything").
	}

	scope := target
	if r.UserID != "" {
		scope = append(scope, leaf(CondUser, OpEquals, r.UserID))
	}
	if r.AllowedServiceName != "" {
		name := r.AllowedServiceName
		if runtime.GOOS == "windows" {
			// serviceNameMatcher folds the extracted request value on
			// Windows (matching legacyServiceNameMatches's strings.EqualFold);
			// folding the authored value here the same way at adapt time
			// keeps both sides of the OpEquals comparison in the same case.
			// GOOS cannot change during a running agent process, so folding
			// once here and once per Extract call agree.
			name = strings.ToLower(name)
		}
		scope = append(scope, leaf(CondServiceName, OpEquals, name))
	}

	return RuleV2{
		ID:         r.ID,
		Version:    1,
		Enabled:    true, // v1 rules have no enabled/disabled concept: always on.
		Priority:   r.Priority,
		Conditions: andOf(scope),
		ExpiresAt:  r.ExpiresAt,
		Outcome: Outcome{
			Verdict: verdictFromDecision(r.Decision),
			Mode:    ModeSilent,
			// Reason is exactly v1's Reason string ("allow"/"deny") — see
			// legacyEvaluate and Decision.Legacy — so a v1-sourced rule's
			// ElevationResponse.Reason is byte-identical whether it comes
			// from the preserved legacy evaluator or from this upgrade path.
			Reason: string(r.Decision),
		},
	}
}

// verdictFromDecision maps the v1 binary decision onto its v2 verdict.
// PolicyDecision only ever holds DecisionAllow or DecisionDeny in practice
// (see policy.go), so this is a total mapping over the values that actually
// occur; an unrecognized value defaults to deny, matching the engine's
// overall default-deny posture.
func verdictFromDecision(d PolicyDecision) Verdict {
	if d == DecisionAllow {
		return VerdictAllow
	}
	return VerdictDeny
}

// opForPattern preserves v1's isGlob() heuristic exactly: a pattern
// containing any of '*', '?', '[' is a glob; anything else is an exact match.
// See legacyIsGlob.
func opForPattern(p string) Operator {
	if strings.ContainsAny(p, "*?[") {
		return OpGlob
	}
	return OpEquals
}

// leaf builds a single-value leaf Condition.
func leaf(kind ConditionKind, op Operator, value string) *Condition {
	return &Condition{Kind: kind, Operator: op, Value: value}
}
