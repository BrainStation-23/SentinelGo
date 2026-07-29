package epm

import (
	"sync/atomic"
	"time"
)

// Engine evaluates elevation requests against a compiled rule set. It holds
// the set behind an atomic.Pointer so Swap can hot-replace policy — a fresh
// bundle landing from policy sync — without stopping the accept loop or
// racing an in-flight evaluation.
//
// NewEngine(rules []PolicyRule) and (*Engine).Evaluate keep their exact pre-v2
// signatures: every existing caller (pipe_windows.go, socket_linux.go,
// socket_darwin.go, policy_test.go) compiles and behaves identically without
// edits. Evaluate is now a thin projection over EvaluateV2 (see Decision.Legacy),
// so the two representations can never drift apart.
type Engine struct {
	set      atomic.Pointer[CompiledRuleSet]
	matchers *MatcherRegistry
	ctxProv  ContextProvider
	now      func() time.Time

	// v1Fallback holds the original PolicyRule slice on the one path where
	// NewEngine's Compile call can fail structurally — more rules than
	// MaxRulesPerBundle. It exists purely so a pathologically large legacy
	// rule set (never bounded by any cap before this package existed) keeps
	// working via the original algorithm rather than silently evaluating
	// against nothing and default-denying every request. nil on every normal
	// path — Compile succeeding is the overwhelmingly common case.
	v1Fallback []PolicyRule
}

// EngineOption configures an Engine built via NewEngineWithSet.
type EngineOption func(*Engine)

// WithContextProvider wires a ContextProvider so EvaluateV2 can fill in
// EvalInput.Context automatically for a caller that does not already supply
// one. Optional — the zero value (nil) makes every context-sourced condition
// Unknown, exactly matching today's behavior since no v1 rule uses one.
func WithContextProvider(p ContextProvider) EngineOption {
	return func(e *Engine) { e.ctxProv = p }
}

// WithMatcherRegistry overrides the default matcher registry — primarily for
// tests that want to exercise a subset of matchers in isolation.
func WithMatcherRegistry(r *MatcherRegistry) EngineOption {
	return func(e *Engine) { e.matchers = r }
}

// WithClock overrides time.Now, for deterministic tests.
func WithClock(now func() time.Time) EngineOption {
	return func(e *Engine) { e.now = now }
}

// NewEngine builds an Engine over rules by upgrading each PolicyRule through
// UpgradeV1 and compiling the result with the default matcher registry. The
// caller is expected to have already loaded rules from durable storage (see
// internal/store.EPMStore) — unchanged from v1.
func NewEngine(rules []PolicyRule) *Engine {
	return NewEngineFromV1(rules, DefaultMatchers())
}

// NewEngineFromV1 builds an Engine over legacy PolicyRule values using reg
// instead of the default registry — exposed so a test can exercise the v1
// upgrade path against a constrained registry.
func NewEngineFromV1(rules []PolicyRule, reg *MatcherRegistry) *Engine {
	e := &Engine{matchers: reg, now: time.Now}

	v2rules := make([]RuleV2, 0, len(rules))
	for _, r := range rules {
		v2rules = append(v2rules, UpgradeV1(r))
	}

	set, _, err := Compile(v2rules, nil, reg)
	if err != nil {
		// Only reachable if rules exceeds MaxRulesPerBundle, which no v1
		// installation was ever bounded by. Fall back to the original
		// algorithm rather than silently default-denying every request.
		e.v1Fallback = rules
		return e
	}
	e.set.Store(set)
	return e
}

// NewEngineWithSet builds an Engine directly over an already-compiled set —
// the path Phase 3's BundleManager uses once policy bundles exist. opts
// default matchers to DefaultMatchers() and the clock to time.Now.
func NewEngineWithSet(set *CompiledRuleSet, opts ...EngineOption) *Engine {
	e := &Engine{matchers: DefaultMatchers(), now: time.Now}
	for _, opt := range opts {
		opt(e)
	}
	e.set.Store(set)
	return e
}

// Swap hot-replaces the compiled rule set. Safe to call concurrently with
// Evaluate/EvaluateV2 — the atomic pointer guarantees a given evaluation sees
// either the old set or the new one in full, never a partial mix. Also clears
// any v1 fallback, since a caller that swaps in a real compiled set has
// unambiguously moved past the fallback path.
func (e *Engine) Swap(set *CompiledRuleSet) {
	e.set.Store(set)
	e.v1Fallback = nil
}

// Evaluate selects the highest-priority rule matching req and returns its
// decision. Signature and behavior are unchanged from v1: when no rule
// matches, the request is denied by default. This is now a thin projection
// over EvaluateV2 (see Decision.Legacy) so the two APIs cannot drift.
func (e *Engine) Evaluate(req ElevationRequest) ElevationResponse {
	if e.v1Fallback != nil {
		return legacyEvaluate(e.v1Fallback, req)
	}
	return e.EvaluateV2(EvalInput{Now: req.Now, Request: upgradeRequest(req)}).Legacy()
}

// candidateResult pairs a CompiledRule with its evaluation outcome for one
// request, so the winner-selection comparison (betterCandidate) does not have
// to re-derive anything from the raw evalResult.
type candidateResult struct {
	rule *CompiledRule
	spec int
	res  evalResult
}

// betterCandidate reports whether a should displace b as the winning match.
//
// Ordering key: specificity descending, then Priority descending, then the
// lexicographically smaller rule ID. This is deliberately IDENTICAL to
// legacyBetterMatch's tie-break — no verdict-family precedence is applied
// here, even though a "deny beats allow on an exact tie" rule would be a
// reasonable general policy-engine property. Adding it would change the
// winner for a constructible edge case (two rules tied on tier and priority,
// one allow and one deny, where the deny rule has the larger ID) relative to
// v1, which TestV1V2Differential must not observe. Preserving exact
// tie-break parity here is what makes that merge gate possible; revisit only
// alongside a deliberate, documented v1-parity break.
func betterCandidate(a, b candidateResult) bool {
	if a.spec != b.spec {
		return a.spec > b.spec
	}
	if a.rule.Priority != b.rule.Priority {
		return a.rule.Priority > b.rule.Priority
	}
	return a.rule.ID < b.rule.ID
}

// EvaluateV2 selects the highest-specificity matching rule and returns the
// full v2 Decision. Unlike Evaluate, this is never routed through the v1
// fallback — a caller reaching for EvaluateV2 wants the v2 feature set
// (Outcome, Explain, Indeterminate), which the fallback path cannot supply;
// the fallback exists solely to keep the legacy Evaluate/ElevationResponse
// contract correct in the one pathological case described on Engine.v1Fallback.
func (e *Engine) EvaluateV2(in EvalInput) Decision {
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	if in.Now.IsZero() {
		in.Now = now().UTC()
	}
	if e.ctxProv != nil && in.Context.Sources == nil && in.Context.CollectedAt.IsZero() {
		in.Context = e.ctxProv.Snapshot()
	}

	set := e.set.Load()
	if set == nil {
		return Decision{Outcome: Outcome{Verdict: VerdictDeny, Reason: "no matching policy (default deny)"}}
	}
	if timeDefaultsUnset(in.Defaults) {
		in.Defaults = set.Defaults
	}

	var best *candidateResult
	for _, cr := range set.candidates(&in.Request) {
		if !cr.EffectiveFrom.IsZero() && cr.EffectiveFrom.After(in.Now) {
			continue
		}
		if !cr.ExpiresAt.IsZero() && cr.ExpiresAt.Before(in.Now) {
			continue
		}

		res := evalTree(cr.Tree, &in, 0)

		matches := false
		spec := res.spec
		switch res.tri {
		case TriTrue:
			matches = true
		case TriUnknown:
			switch cr.OnUnknown {
			case "match":
				matches = true
			case "skip":
				matches = false
			default:
				matches = cr.Outcome.Verdict.IsDenyFamily()
			}
			if matches {
				// evalTree only computes a "satisfied subtree" specificity
				// when the node itself resolved True; an OnUnknown-forced
				// match has no such number, so fall back to the rule's
				// compile-time upper bound rather than reporting 0.
				spec = cr.StaticSpec
			}
		}
		if !matches {
			continue
		}

		cand := candidateResult{rule: cr, spec: spec, res: res}
		if best == nil || betterCandidate(cand, *best) {
			best = &cand
		}
	}

	if best == nil {
		return Decision{Outcome: Outcome{Verdict: VerdictDeny, Reason: "no matching policy (default deny)"}}
	}

	d := Decision{
		Outcome:       best.rule.Outcome,
		RuleID:        best.rule.ID,
		RuleVersion:   best.rule.Version,
		GroupID:       best.rule.GroupID,
		BundleID:      set.BundleID,
		Specificity:   best.spec,
		Priority:      best.rule.Priority,
		Matched:       dedupKinds(best.res.matched),
		Indeterminate: dedupKinds(best.res.indeterminate),
	}
	if in.Explain {
		d.Explain = best.res.explain
	}
	return d
}

// timeDefaultsUnset reports whether d is the zero TimeDefaults — used to
// decide whether EvaluateV2 should fall back to the compiled set's own
// Defaults. Written as a field-by-field check rather than `d ==
// TimeDefaults{}` because BusinessDays ([]string) makes the struct
// non-comparable with ==.
func timeDefaultsUnset(d TimeDefaults) bool {
	return d.BusinessHoursStart == "" && d.BusinessHoursEnd == "" &&
		d.Timezone == "" && len(d.BusinessDays) == 0
}

// dedupKinds returns kinds with duplicates removed, preserving first-seen
// order, so Decision.Matched/Indeterminate read as a clean set even though a
// condition tree can visit the same ConditionKind more than once (e.g. two
// sibling CondUserGroup leaves under an OR).
func dedupKinds(kinds []ConditionKind) []ConditionKind {
	if len(kinds) == 0 {
		return nil
	}
	seen := make(map[ConditionKind]bool, len(kinds))
	out := make([]ConditionKind, 0, len(kinds))
	for _, k := range kinds {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
