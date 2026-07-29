package epm

import (
	"path"
	"runtime"
	"strings"
	"time"
)

// This file preserves the original (v1) linear-pass evaluator byte-for-behavior
// identical, under unexported names, so it can serve as the oracle in
// TestV1V2Differential (adapter_v1_diff_test.go): every (rule, request) pair
// must produce the same (Allowed, PolicyID) from this code and from the v2
// engine reached through UpgradeV1 (see adapter_v1.go). Engine.Evaluate itself
// is now a thin projection over the v2 engine — see engine_v2.go — so this is
// the only remaining copy of the original algorithm.
//
// Kept in-tree, unmodified, for at least two releases after the v2 engine
// ships; see the plan's rollback notes. Do not "clean this up" by merging it
// into the v2 path — its entire value is being a mechanically independent
// second implementation to diff against.

// Legacy match tiers, highest wins. A rule scores the tier of the most
// specific field it matched on; rules that don't match on any target field
// are wildcards. These are the exact numeric values specificity.go's weights
// preserve for the v2 engine.
const (
	legacyTierHash      = 300
	legacyTierPublisher = 200
	legacyTierPathExact = 100
	legacyTierPathGlob  = 50
	legacyTierWildcard  = 10
	legacyTierNone      = -1 // rule does not match the request at all
)

// legacyEvaluate selects the highest-priority rule matching req and returns
// its decision. When no rule matches, the request is denied by default.
func legacyEvaluate(rules []PolicyRule, req ElevationRequest) ElevationResponse {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	bestTier := legacyTierNone
	bestPriority := 0
	var best *PolicyRule

	for i := range rules {
		rule := &rules[i]

		if !rule.ExpiresAt.IsZero() && rule.ExpiresAt.Before(now) {
			continue // expired: skip as if it did not exist
		}
		if rule.UserID != "" && rule.UserID != req.UserID {
			continue // scoped to a different user
		}

		tier := legacyMatchTier(rule, req)
		if tier == legacyTierNone {
			continue
		}

		if best == nil || legacyBetterMatch(tier, rule, bestTier, bestPriority, best) {
			bestTier = tier
			bestPriority = rule.Priority
			best = rule
		}
	}

	if best == nil {
		return ElevationResponse{
			Allowed: false,
			Reason:  "no matching policy (default deny)",
		}
	}

	return ElevationResponse{
		Allowed:  best.Decision == DecisionAllow,
		PolicyID: best.ID,
		Reason:   string(best.Decision),
	}
}

func legacyBetterMatch(tier int, rule *PolicyRule, bestTier, bestPriority int, best *PolicyRule) bool {
	if tier != bestTier {
		return tier > bestTier
	}
	if rule.Priority != bestPriority {
		return rule.Priority > bestPriority
	}
	return rule.ID < best.ID
}

func legacyMatchTier(rule *PolicyRule, req ElevationRequest) int {
	tier := legacyBaseTier(rule, req)
	if tier == legacyTierNone {
		return legacyTierNone
	}
	if !legacyServiceNameMatches(rule, req) {
		return legacyTierNone
	}
	return tier
}

func legacyBaseTier(rule *PolicyRule, req ElevationRequest) int {
	if rule.ScriptHash != "" {
		if rule.AppPath == "" || !legacyPathMatches(rule.AppPath, req.AppPath) {
			return legacyTierNone
		}
		if rule.ScriptHash != req.ScriptHash {
			return legacyTierNone
		}
		if rule.AllowedArgs != "" && strings.TrimSpace(req.ActualArgs) != rule.AllowedArgs {
			return legacyTierNone
		}
		return legacyTierHash
	}

	if rule.AppHash != "" {
		if rule.AppHash == req.AppHash {
			return legacyTierHash
		}
		return legacyTierNone
	}
	if rule.Publisher != "" {
		if rule.Publisher == req.Publisher {
			return legacyTierPublisher
		}
		return legacyTierNone
	}
	if rule.AppPath != "" {
		if !legacyPathMatches(rule.AppPath, req.AppPath) {
			return legacyTierNone
		}
		if legacyIsGlob(rule.AppPath) {
			return legacyTierPathGlob
		}
		return legacyTierPathExact
	}
	return legacyTierWildcard
}

func legacyPathMatches(pattern, actualPath string) bool {
	if legacyIsGlob(pattern) {
		ok, err := path.Match(legacyNormalizeSeparators(pattern), legacyNormalizeSeparators(actualPath))
		return err == nil && ok
	}
	return pattern == actualPath
}

func legacyServiceNameMatches(rule *PolicyRule, req ElevationRequest) bool {
	if rule.AllowedServiceName == "" {
		return true
	}
	if req.RequestedServiceName == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(rule.AllowedServiceName, req.RequestedServiceName)
	}
	return rule.AllowedServiceName == req.RequestedServiceName
}

func legacyIsGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func legacyNormalizeSeparators(s string) string {
	return strings.ReplaceAll(s, `\`, "/")
}
