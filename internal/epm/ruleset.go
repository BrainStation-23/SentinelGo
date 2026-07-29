package epm

import (
	"regexp"
	"time"
)

// RuleV2 is the modern rule representation: a named Condition tree plus an
// Outcome, replacing PolicyRule's five hardcoded target fields with an
// arbitrary nested AND/OR/NOT tree over any of the ConditionKinds declared in
// condition.go. A v1 PolicyRule lowers into exactly one RuleV2 — see
// UpgradeV1 (adapter_v1.go) — so the engine has a single rule representation
// regardless of which wire format produced it.
type RuleV2 struct {
	ID       string
	GroupID  string // "" if not a member of any RuleGroup
	Version  int
	Enabled  bool
	Priority int
	// Conditions is nil for a wildcard rule — matches every request, exactly
	// like a v1 PolicyRule with no AppPath/AppHash/Publisher set.
	Conditions *Condition
	Outcome    Outcome
	// EffectiveFrom, if non-zero, makes the rule inactive before that instant
	// — new in v2; v1 rules never set it.
	EffectiveFrom time.Time
	ExpiresAt     time.Time
	// OnUnknown overrides the verdict-family default for how a top-level
	// Unknown tree result affects whether this rule matches at all:
	//   - "" (default): family default — an allow-family rule does not
	//     match on Unknown (nothing is granted on an unverifiable fact); a
	//     deny-family rule does match (the denial stands).
	//   - "match": Unknown always makes the rule match, regardless of
	//     verdict family — the escape hatch for "block unsigned" style rules,
	//     where CondSigned's inherent ambiguity should count against the
	//     target even though Deny is already the family default.
	//   - "skip": Unknown always makes the rule NOT match, regardless of
	//     verdict family — for a rule the author wants to simply step aside
	//     on any unverifiable fact rather than fail closed.
	// This is a rule-level override of the top-level result, not a per-leaf
	// "treat this one Unknown condition as absent" — see evalTree
	// (compile.go) for how Unknown propagates up through AND/OR/NOT first.
	OnUnknown string
	Labels    []string
}

// RuleGroup folds a shared condition prefix and priority boost onto every
// member rule at Compile time: a member's tree becomes AND(group.Conditions,
// member.Conditions) and its priority becomes group.Priority + member.Priority.
// This has no runtime cost — the fold happens once, at compile time — and the
// AND specificity composition (specificity.go) already produces the right
// number for the combined tree without any group-specific logic.
type RuleGroup struct {
	ID         string
	Name       string
	Enabled    bool
	Priority   int
	Conditions *Condition
}

// compiledNode is a Condition with its Matcher resolved and its regex (if
// OpRegex) pre-compiled, so Compile is the only place matcher lookup or
// regexp.Compile ever happens — never on the per-request evaluation path.
type compiledNode struct {
	// Leaf fields (kind != "").
	kind     ConditionKind
	matcher  Matcher
	operator Operator
	value    string
	values   []string
	negate   bool
	regex    *regexp.Regexp // non-nil only when operator == OpRegex
	tz       string

	// Branch fields (logic != "").
	logic    LogicOp
	children []*compiledNode
}

func (n *compiledNode) isLeaf() bool { return n != nil && n.kind != "" }

// CompiledRule is one RuleV2 after Compile: its tree fully resolved, its
// specificity upper bound precomputed, and — when derivable — an index hint
// so Engine.EvaluateV2 does not have to test every rule against every
// request.
type CompiledRule struct {
	ID, GroupID, BundleID    string
	Version                  int
	Priority                 int
	Outcome                  Outcome
	Tree                     *compiledNode
	EffectiveFrom, ExpiresAt time.Time
	// StaticSpec is the compile-time upper bound on this rule's specificity —
	// computed with OR resolved to its MAXIMUM child (orSpecificity's dual),
	// since at compile time it is not yet known which OR branch, if any, will
	// actually fire. Used only to order CompiledRuleSet.rules for a
	// deterministic, specificity-descending evaluation order; the true,
	// per-request specificity (computed with OR resolved to whichever branch
	// actually matched) is what Decision.Specificity reports.
	StaticSpec int
	// OnUnknown mirrors RuleV2.OnUnknown; see that field's doc comment.
	OnUnknown string
	// ReqHash/ReqExactPath are index hints: when non-empty, this rule was
	// determined at compile time to require an exact SHA-256 or exact
	// (non-glob) path match somewhere in its tree, and is filed under that key
	// in CompiledRuleSet.byHash/byExactPath instead of the unindexed bucket.
	// See deriveIndexHints (compile.go).
	ReqHash, ReqExactPath string
}

// CompiledRuleSet is the immutable, ready-to-evaluate form of a policy bundle
// (or, for a v1-sourced Engine, of the upgraded PolicyRule slice). Engine
// holds one behind an atomic.Pointer so Swap can hot-replace policy without
// stopping the accept loop — see engine_v2.go.
type CompiledRuleSet struct {
	Generation int64
	BundleID   string

	// rules is every enabled, successfully compiled rule, sorted by
	// StaticSpec descending (ties broken by ID ascending) so iteration order
	// is deterministic regardless of input order.
	rules       []*CompiledRule
	byHash      map[string][]*CompiledRule
	byExactPath map[string][]*CompiledRule
	unindexed   []*CompiledRule

	Defaults TimeDefaults
}

// candidates returns every CompiledRule that could possibly match req: rules
// indexed under its exact hash or exact path, plus every unindexed rule
// (globs, publisher-only, context-only, OR-rooted, and wildcard rules — any
// tree shape deriveIndexHints could not reduce to a single required exact
// value). No rule that could match a request is ever excluded by this
// filter — see deriveIndexHints's correctness note.
func (s *CompiledRuleSet) candidates(req *ElevationRequestV2) []*CompiledRule {
	if s == nil {
		return nil
	}
	out := make([]*CompiledRule, 0, len(s.unindexed)+4)
	if req.AppHash != "" {
		out = append(out, s.byHash[normalizeHashKey(req.AppHash)]...)
	}
	if req.AppPath != "" {
		out = append(out, s.byExactPath[normalizeSeparators(req.AppPath)]...)
	}
	out = append(out, s.unindexed...)
	return out
}
