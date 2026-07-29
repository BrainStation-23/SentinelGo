package epm

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CompileIssue reports a single rule that Compile could not use, without
// failing the whole bundle over one bad rule. A rule with an issue is simply
// excluded from the compiled set — fail closed: it grants nothing, but it
// also does not block every other rule in the bundle from taking effect.
// BundleManager (Phase 3) surfaces these back to the console so an author can
// fix the offending rule.
type CompileIssue struct {
	RuleID  string
	GroupID string
	Message string
}

func (i CompileIssue) String() string {
	if i.RuleID == "" {
		return i.Message
	}
	return fmt.Sprintf("rule %q: %s", i.RuleID, i.Message)
}

// Compile validates and lowers a rule set into an evaluation-ready
// CompiledRuleSet. All regex compilation, glob/structural validation, matcher
// lookup, structural-cap enforcement, and rule-group folding happen here —
// once per policy sync, never per request.
//
// A structural problem with the WHOLE bundle (too many rules, a nil registry)
// is a hard error: the caller should reject the bundle outright rather than
// apply a truncated version of it. A problem with ONE rule is a CompileIssue:
// that rule is dropped, everything else compiles and applies normally.
func Compile(rules []RuleV2, groups []RuleGroup, reg *MatcherRegistry) (*CompiledRuleSet, []CompileIssue, error) {
	if reg == nil {
		return nil, nil, fmt.Errorf("epm: Compile: nil matcher registry")
	}
	if len(rules) > MaxRulesPerBundle {
		return nil, nil, fmt.Errorf("epm: Compile: %d rules exceeds MaxRulesPerBundle (%d)", len(rules), MaxRulesPerBundle)
	}

	groupByID := make(map[string]RuleGroup, len(groups))
	for _, g := range groups {
		groupByID[g.ID] = g
	}

	set := &CompiledRuleSet{
		byHash:      make(map[string][]*CompiledRule),
		byExactPath: make(map[string][]*CompiledRule),
	}
	var issues []CompileIssue

	for _, r := range rules {
		if !r.Enabled {
			continue
		}

		tree := r.Conditions
		priority := r.Priority
		if r.GroupID != "" {
			g, ok := groupByID[r.GroupID]
			if !ok {
				issues = append(issues, CompileIssue{RuleID: r.ID, GroupID: r.GroupID,
					Message: fmt.Sprintf("references unknown group %q", r.GroupID)})
				continue
			}
			if !g.Enabled {
				continue
			}
			tree = andOf([]*Condition{g.Conditions, r.Conditions})
			priority += g.Priority
		}

		nodeCount := 0
		if err := validateConditionShape(tree, 1, &nodeCount, reg); err != nil {
			issues = append(issues, CompileIssue{RuleID: r.ID, Message: err.Error()})
			continue
		}

		compiled, err := compileNode(tree, reg)
		if err != nil {
			issues = append(issues, CompileIssue{RuleID: r.ID, Message: err.Error()})
			continue
		}

		cr := &CompiledRule{
			ID:            r.ID,
			GroupID:       r.GroupID,
			Version:       r.Version,
			Priority:      priority,
			Outcome:       r.Outcome,
			Tree:          compiled,
			EffectiveFrom: r.EffectiveFrom,
			ExpiresAt:     r.ExpiresAt,
			OnUnknown:     r.OnUnknown,
			StaticSpec:    staticSpecificity(compiled),
		}
		cr.ReqHash, cr.ReqExactPath = deriveIndexHints(compiled)

		switch {
		case cr.ReqHash != "":
			set.byHash[cr.ReqHash] = append(set.byHash[cr.ReqHash], cr)
		case cr.ReqExactPath != "":
			set.byExactPath[cr.ReqExactPath] = append(set.byExactPath[cr.ReqExactPath], cr)
		default:
			set.unindexed = append(set.unindexed, cr)
		}
		set.rules = append(set.rules, cr)
	}

	sort.SliceStable(set.rules, func(i, j int) bool {
		if set.rules[i].StaticSpec != set.rules[j].StaticSpec {
			return set.rules[i].StaticSpec > set.rules[j].StaticSpec
		}
		return set.rules[i].ID < set.rules[j].ID
	})

	return set, issues, nil
}

// validateConditionShape enforces the structural caps (MaxConditionDepth,
// MaxConditionNodes) and node well-formedness (exactly one of leaf/branch/
// wildcard, valid operator, valid logic, NOT has exactly one child, a leaf's
// Kind is registered) before any Matcher lookup or regex compilation is
// attempted, so a pathological tree is rejected cheaply.
func validateConditionShape(c *Condition, depth int, nodeCount *int, reg *MatcherRegistry) error {
	if c.isWildcard() {
		return nil
	}
	if depth > MaxConditionDepth {
		return fmt.Errorf("condition tree exceeds max depth %d", MaxConditionDepth)
	}
	*nodeCount++
	if *nodeCount > MaxConditionNodes {
		return fmt.Errorf("condition tree exceeds max node count %d", MaxConditionNodes)
	}

	switch {
	case c.isLeaf() && c.isBranch():
		return fmt.Errorf("condition node sets both kind %q and logic %q", c.Kind, c.Logic)
	case c.isLeaf():
		if _, ok := reg.Lookup(c.Kind); !ok {
			return fmt.Errorf("unknown condition kind %q", c.Kind)
		}
		op := c.Operator
		if op == "" {
			op = OpEquals
		}
		if !op.Valid() {
			return fmt.Errorf("condition %q: invalid operator %q", c.Kind, c.Operator)
		}
		if op == OpRegex {
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("condition %q: invalid regex %q: %w", c.Kind, c.Value, err)
			}
		}
		return nil
	case c.isBranch():
		if !c.Logic.Valid() {
			return fmt.Errorf("invalid logic operator %q", c.Logic)
		}
		if len(c.Children) == 0 {
			return fmt.Errorf("logic %q branch has no children", c.Logic)
		}
		if c.Logic == LogicNot && len(c.Children) != 1 {
			return fmt.Errorf("logic \"not\" must have exactly one child, got %d", len(c.Children))
		}
		for _, child := range c.Children {
			if err := validateConditionShape(child, depth+1, nodeCount, reg); err != nil {
				return err
			}
		}
		return nil
	default:
		// Unreachable given isWildcard's check above, but fail closed rather
		// than silently accepting an ambiguous node.
		return fmt.Errorf("condition node is neither leaf, branch, nor wildcard")
	}
}

// compileNode lowers a validated *Condition into a *compiledNode, resolving
// each leaf's Matcher and pre-compiling any regex. Assumes
// validateConditionShape already accepted c.
func compileNode(c *Condition, reg *MatcherRegistry) (*compiledNode, error) {
	if c.isWildcard() {
		return nil, nil
	}
	if c.isLeaf() {
		m, ok := reg.Lookup(c.Kind)
		if !ok {
			return nil, fmt.Errorf("unknown condition kind %q", c.Kind)
		}
		op := c.Operator
		if op == "" {
			op = OpEquals
		}
		node := &compiledNode{
			kind: c.Kind, matcher: m, operator: op,
			value: c.Value, values: c.Values, negate: c.Negate, tz: c.Timezone,
		}
		if op == OpRegex {
			re, err := regexp.Compile(c.Value)
			if err != nil {
				return nil, fmt.Errorf("condition %q: invalid regex %q: %w", c.Kind, c.Value, err)
			}
			node.regex = re
		}
		return node, nil
	}

	children := make([]*compiledNode, 0, len(c.Children))
	for _, child := range c.Children {
		cn, err := compileNode(child, reg)
		if err != nil {
			return nil, err
		}
		if cn == nil {
			// A wildcard child of a branch always evaluates true and
			// contributes WeightWildcard; represent it as an explicit
			// always-true leaf rather than nil so branch evaluation does not
			// need a special case for "child compiled to nothing."
			cn = &compiledNode{kind: "", matcher: wildcardMatcher{}, operator: OpIsTrue, value: "true"}
		}
		children = append(children, cn)
	}
	return &compiledNode{logic: c.Logic, children: children}, nil
}

// wildcardMatcher backs an explicit always-true branch child (see
// compileNode). Its Kind is "" and it is never looked up through the
// registry — only ever constructed directly here.
type wildcardMatcher struct{}

func (wildcardMatcher) Kind() ConditionKind                 { return "" }
func (wildcardMatcher) Weight() int                         { return WeightWildcard }
func (wildcardMatcher) MaxAge() time.Duration               { return 0 }
func (wildcardMatcher) Extract(*EvalInput) ([]string, bool) { return []string{"true"}, true }

// andOf builds a LogicAnd Condition over the non-wildcard members of parts,
// collapsing to a single member (or nil) when that suffices — used both by
// Compile's group-folding and by UpgradeV1.
func andOf(parts []*Condition) *Condition {
	var kept []*Condition
	for _, p := range parts {
		if !p.isWildcard() {
			kept = append(kept, p)
		}
	}
	switch len(kept) {
	case 0:
		return nil
	case 1:
		return kept[0]
	default:
		return &Condition{Logic: LogicAnd, Children: kept}
	}
}

// --- Tree evaluation ---

// evalResult is one node's (or subtree's) evaluation outcome, threaded back
// up the recursion so a rule's aggregate Matched/Indeterminate/Explain can be
// assembled from its root result alone.
type evalResult struct {
	tri           Tri
	spec          int
	matched       []ConditionKind
	indeterminate []ConditionKind
	explain       []ExplainStep
}

// evalTree evaluates node against in, returning its tri-state result and the
// specificity that result earned (see specificity.go's composition rules).
// A nil node is the wildcard case: always true, always WeightWildcard.
func evalTree(node *compiledNode, in *EvalInput, depth int) evalResult {
	if node == nil {
		return evalResult{tri: TriTrue, spec: WeightWildcard}
	}
	if node.isLeaf() {
		return evalLeafNode(node, in, depth)
	}
	return evalBranchNode(node, in, depth)
}

func evalLeafNode(node *compiledNode, in *EvalInput, depth int) evalResult {
	extracted, known := node.matcher.Extract(in)

	var tri Tri
	if !known {
		tri = TriUnknown
	} else {
		matched := false
		for _, ev := range extracted {
			if applyOperator(node.operator, node.value, node.values, node.regex, ev) {
				matched = true
				break
			}
		}
		tri = triFromBool(matched)
		if node.negate {
			tri = triNot(tri)
		}
	}

	res := evalResult{tri: tri}
	if tri == TriTrue {
		res.spec = leafSpecificity(node.matcher.Weight(), node.operator, node.negate)
		res.matched = []ConditionKind{node.kind}
	}
	if tri == TriUnknown {
		res.indeterminate = []ConditionKind{node.kind}
	}
	if in.Explain {
		res.explain = []ExplainStep{{
			Kind: node.kind, Operator: node.operator, Value: node.value, Result: tri, Depth: depth,
		}}
	}
	return res
}

func evalBranchNode(node *compiledNode, in *EvalInput, depth int) evalResult {
	children := make([]evalResult, len(node.children))
	for i, c := range node.children {
		children[i] = evalTree(c, in, depth+1)
	}

	res := evalResult{}
	for _, c := range children {
		res.matched = append(res.matched, c.matched...)
		res.indeterminate = append(res.indeterminate, c.indeterminate...)
		res.explain = append(res.explain, c.explain...)
	}

	switch node.logic {
	case LogicNot:
		res.tri = triNot(children[0].tri)
		res.spec = notSpecificity(children[0].spec)
	case LogicOr:
		tri := TriFalse
		if len(children) == 0 {
			tri = TriFalse
		}
		for _, c := range children {
			tri = triOr(tri, c.tri)
		}
		res.tri = tri
		if tri == TriTrue {
			// Only the branches that actually fired contribute — see
			// orSpecificity's doc comment.
			var trueSpecs []int
			for _, c := range children {
				if c.tri == TriTrue {
					trueSpecs = append(trueSpecs, c.spec)
				}
			}
			res.spec = orSpecificity(trueSpecs)
		} else {
			var allSpecs []int
			for _, c := range children {
				allSpecs = append(allSpecs, c.spec)
			}
			res.spec = orSpecificity(allSpecs)
		}
	default: // LogicAnd
		tri := TriTrue
		for _, c := range children {
			tri = triAnd(tri, c.tri)
		}
		res.tri = tri
		specs := make([]int, len(children))
		for i, c := range children {
			specs[i] = c.spec
		}
		res.spec = andSpecificity(specs)
	}
	return res
}

// staticSpecificity computes the compile-time upper bound used only to order
// CompiledRuleSet.rules: OR resolves to the MAXIMUM of its children (the
// dual of orSpecificity's per-request minimum-of-matched-branches), since at
// compile time it is not yet known which branch, if any, will actually fire.
func staticSpecificity(node *compiledNode) int {
	if node == nil {
		return WeightWildcard
	}
	if node.isLeaf() {
		return leafSpecificity(node.matcher.Weight(), node.operator, node.negate)
	}
	specs := make([]int, len(node.children))
	for i, c := range node.children {
		specs[i] = staticSpecificity(c)
	}
	switch node.logic {
	case LogicNot:
		return notSpecificity(specs[0])
	case LogicOr:
		max := specs[0]
		for _, s := range specs[1:] {
			if s > max {
				max = s
			}
		}
		return max
	default:
		return andSpecificity(specs)
	}
}

// deriveIndexHints looks for a top-level (or AND-nested) exact SHA-256 or
// exact-path requirement in tree, so CompiledRuleSet can file the rule under
// that key instead of the unindexed bucket. This is purely an evaluation-time
// optimization: a rule this cannot reduce to a single required exact value
// (an OR-rooted tree, a glob path, a publisher-only rule, a context-only
// rule, a wildcard) simply lands in the unindexed bucket, which is always
// still checked in full — see CompiledRuleSet.candidates. Under-detection
// only costs performance, never correctness.
func deriveIndexHints(tree *compiledNode) (hash, exactPath string) {
	if tree == nil {
		return "", ""
	}
	if tree.isLeaf() {
		return leafIndexHint(tree)
	}
	if tree.logic != LogicAnd {
		return "", ""
	}
	for _, c := range tree.children {
		var h, p string
		if c.isLeaf() {
			h, p = leafIndexHint(c)
		} else if c.logic == LogicAnd {
			h, p = deriveIndexHints(c)
		}
		if h != "" && hash == "" {
			hash = h
		}
		if p != "" && exactPath == "" {
			exactPath = p
		}
	}
	return hash, exactPath
}

func leafIndexHint(leaf *compiledNode) (hash, exactPath string) {
	if leaf.negate || leaf.operator != OpEquals || leaf.value == "" {
		return "", ""
	}
	switch leaf.kind {
	case CondSHA256:
		return normalizeHashKey(leaf.value), ""
	case CondPath:
		return "", normalizeSeparators(leaf.value)
	}
	return "", ""
}

func normalizeHashKey(s string) string {
	return strings.ToLower(s)
}

// --- Operators ---

// applyOperator reports whether ev (one value extracted by a Matcher)
// satisfies op against the leaf's authored value/values. Negation is applied
// by the caller (evalLeafNode), not here, so this function's return is always
// the un-negated comparison result.
func applyOperator(op Operator, value string, values []string, re *regexp.Regexp, ev string) bool {
	switch op {
	case OpEquals:
		return ev == value
	case OpIn:
		for _, v := range values {
			if ev == v {
				return true
			}
		}
		return false
	case OpGlob:
		ok, err := path.Match(value, ev)
		return err == nil && ok
	case OpPrefix:
		return strings.HasPrefix(ev, value)
	case OpSuffix:
		return strings.HasSuffix(ev, value)
	case OpContains:
		return strings.Contains(ev, value)
	case OpRegex:
		return re != nil && re.MatchString(ev)
	case OpVersionGTE:
		return compareVersions(ev, value) >= 0
	case OpVersionLT:
		return compareVersions(ev, value) < 0
	case OpBetween:
		if len(values) != 2 {
			return false
		}
		return betweenCompare(ev, values[0], values[1])
	case OpIsTrue:
		return ev == "true"
	case OpIsFalse:
		return ev == "false"
	default:
		return false
	}
}

// betweenCompare reports whether lo <= v <= hi. Tries numeric-version
// comparison first (so "10.5" is correctly between "10.0" and "11.0" despite
// failing a lexical compare); falls back to a plain lexical compare (which
// also correctly handles "HH:MM" time-of-day bounds, since zero-padded
// 24-hour strings sort lexically in time order).
func betweenCompare(v, lo, hi string) bool {
	if isVersionLike(v) && isVersionLike(lo) && isVersionLike(hi) {
		return compareVersions(v, lo) >= 0 && compareVersions(v, hi) <= 0
	}
	return v >= lo && v <= hi
}

func isVersionLike(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// compareVersions compares two dot-separated numeric version strings
// segment by segment (10.5 > 10.0.9 > 9.9.9), treating a missing trailing
// segment as 0 and a non-numeric segment as 0 rather than failing — a
// malformed version string should compare low, not crash the evaluator.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := versionSegment(as, i), versionSegment(bs, i)
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionSegment(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(parts[i]))
	if err != nil {
		return 0
	}
	return v
}
