package epm

import "testing"

// TestWeights_MatchLegacyTiersExactly pins the property the whole composition
// scheme depends on: the five weights that existed in v1 (legacy_engine.go's
// legacyTierXxx constants) carry forward unchanged. Any drift here would
// silently reorder rule precedence for every existing deployed policy.
func TestWeights_MatchLegacyTiersExactly(t *testing.T) {
	tests := []struct {
		name         string
		weight, tier int
	}{
		{"hash", WeightHash, legacyTierHash},
		{"publisher", WeightPublisher, legacyTierPublisher},
		{"path exact", WeightPathExact, legacyTierPathExact},
		{"path glob", WeightPathGlob, legacyTierPathGlob},
		{"wildcard", WeightWildcard, legacyTierWildcard},
	}
	for _, tc := range tests {
		if tc.weight != tc.tier {
			t.Errorf("%s: Weight=%d, legacy tier=%d — must match exactly", tc.name, tc.weight, tc.tier)
		}
	}
}

// TestAndSpecificity_PublisherTierNeverCrossesHash is the invariant the v1
// tier-preservation design leans on: an AND branch whose STRONGEST leaf is at
// or below WeightPublisher (200) can never reach WeightHash (300), no matter
// how many other weak conditions are ANDed on — andSiblingCap (99) guarantees
// 200+99=299 < 300. This is what lets a composite rule like `publisher AND
// user AND business_hours` be more specific than a bare publisher rule while
// still never outranking any rule carrying an exact hash — the property the
// v1→v2 migration depends on, since no v1 rule can produce anything stronger
// than a publisher-rooted tree (see adapter_v1.go).
//
// This guarantee is deliberately NOT universal: WeightHashWeak (280) and
// WeightBundleID (250) sit close enough to WeightHash that a composite tree
// rooted at one of them CAN exceed 300 (250+99=349). That is intentional, not
// a gap — a SHA-1 or bundle-identifier match is itself a comparably strong,
// new-in-v2 identity claim with no v1 equivalent, so there is no back-compat
// requirement constraining it the way there is for publisher, and letting it
// occasionally outrank a bare, unqualified SHA-256 rule when combined with
// other strong conditions is a defensible policy-authoring outcome rather
// than a bug.
func TestAndSpecificity_PublisherTierNeverCrossesHash(t *testing.T) {
	// Publisher (200) plus every weight at or below its own strength, summed
	// as siblings — even in the worst case, capped sibling contribution must
	// keep the total under 300.
	weightsAtOrBelowPublisher := []int{
		WeightPackage, WeightProductName, WeightPathExact,
		WeightFileName, WeightArgsExact, WeightServiceName, WeightPathGlob,
		WeightUser, WeightParentChild, WeightUserGroup, WeightOrgUnit, WeightPosture,
	}
	children := append([]int{WeightPublisher}, weightsAtOrBelowPublisher...)

	got := andSpecificity(children)
	if got >= WeightHash {
		t.Errorf("andSpecificity(publisher + everything at or below it) = %d, must stay below WeightHash (%d)", got, WeightHash)
	}
}

func TestAndSpecificity_MaxPlusCappedRest(t *testing.T) {
	tests := []struct {
		name     string
		children []int
		want     int
	}{
		{"single child", []int{200}, 200},
		{"max plus small siblings", []int{200, 40, 30}, 200 + (40+30)/4},
		{"empty is wildcard", nil, WeightWildcard},
		{"sibling sum capped at 99", []int{300, 100, 100, 100, 100}, 300 + andSiblingCap},
	}
	for _, tc := range tests {
		if got := andSpecificity(tc.children); got != tc.want {
			t.Errorf("andSpecificity(%v) = %d, want %d", tc.children, got, tc.want)
		}
	}
}

func TestOrSpecificity_IsMinimumOfChildren(t *testing.T) {
	tests := []struct {
		name     string
		children []int
		want     int
	}{
		{"picks the weakest", []int{300, 50, 200}, 50},
		{"single child", []int{300}, 300},
		{"empty is wildcard", nil, WeightWildcard},
	}
	for _, tc := range tests {
		if got := orSpecificity(tc.children); got != tc.want {
			t.Errorf("orSpecificity(%v) = %d, want %d", tc.children, got, tc.want)
		}
	}
}

func TestNotSpecificity_AppliesQuarterDiscount(t *testing.T) {
	if got, want := notSpecificity(300), 75; got != want {
		t.Errorf("notSpecificity(300) = %d, want %d", got, want)
	}
	if got, want := notSpecificity(40), 10; got != want {
		t.Errorf("notSpecificity(40) = %d, want %d", got, want)
	}
}

func TestLeafSpecificity_OperatorDiscounts(t *testing.T) {
	tests := []struct {
		op   Operator
		want int
	}{
		{OpEquals, 100},
		{OpIn, 100},
		{OpIsTrue, 100},
		{OpIsFalse, 100},
		{OpPrefix, 60},
		{OpSuffix, 60},
		{OpContains, 60},
		{OpGlob, 50},
		{OpRegex, 50},
		{OpVersionGTE, 40},
		{OpVersionLT, 40},
		{OpBetween, 40},
	}
	for _, tc := range tests {
		if got := leafSpecificity(WeightPathExact, tc.op, false); got != tc.want {
			t.Errorf("leafSpecificity(100, %s, false) = %d, want %d", tc.op, got, tc.want)
		}
	}
}

func TestLeafSpecificity_NegateAppliesQuarterDiscount(t *testing.T) {
	got := leafSpecificity(WeightPathExact, OpEquals, true)
	want := 25 // 100 * 1.0 * 0.25
	if got != want {
		t.Errorf("leafSpecificity(100, eq, negate=true) = %d, want %d", got, want)
	}
}

// --- End-to-end through Compile + EvaluateV2 ---

func TestSpecificity_CompositeNeverOutranksBareHash(t *testing.T) {
	compositeRule := RuleV2{
		ID: "composite", Enabled: true, Priority: 1000, // even a huge priority edge...
		Conditions: &Condition{Logic: LogicAnd, Children: []*Condition{
			leaf(CondPublisher, OpEquals, "Contoso Inc"),
			leaf(CondUser, OpEquals, "alice"),
		}},
		Outcome: Outcome{Verdict: VerdictDeny},
	}
	hashRule := RuleV2{
		ID: "hash", Enabled: true, Priority: 0, // ...cannot rescue it: specificity is checked first.
		Conditions: leaf(CondSHA256, OpEquals, "abc123"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}

	set, issues, err := Compile([]RuleV2{compositeRule, hashRule}, nil, DefaultMatchers())
	if err != nil || len(issues) != 0 {
		t.Fatalf("Compile: err=%v issues=%v", err, issues)
	}
	engine := NewEngineWithSet(set)

	d := engine.EvaluateV2(EvalInput{
		Now: diffRefTime,
		Request: ElevationRequestV2{
			UserID: "alice", Publisher: "Contoso Inc", AppHash: "abc123",
		},
	})
	if d.RuleID != "hash" {
		t.Fatalf("winner = %q, want \"hash\" — specificity must beat priority when priority is the tie-break, not the primary key", d.RuleID)
	}
	if d.Outcome.Verdict != VerdictAllow {
		t.Errorf("verdict = %s, want allow", d.Outcome.Verdict)
	}
}

func TestSpecificity_ORContributesOnlyTheMatchedBranch(t *testing.T) {
	// publisher(200) OR user(40): when the publisher branch is what actually
	// matches, the rule's specificity should reflect ~200 territory (the
	// stronger, satisfied branch), not the weaker sibling — proving
	// "only the branch that actually matched contributes" is really about the
	// SATISFIED branch(es), and with only one branch true, that branch's own
	// weight governs.
	rule := RuleV2{
		ID: "or-rule", Enabled: true,
		Conditions: &Condition{Logic: LogicOr, Children: []*Condition{
			leaf(CondPublisher, OpEquals, "Contoso Inc"),
			leaf(CondUser, OpEquals, "nobody-matches-this"),
		}},
		Outcome: Outcome{Verdict: VerdictAllow},
	}
	set, _, err := Compile([]RuleV2{rule}, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	d := NewEngineWithSet(set).EvaluateV2(EvalInput{
		Now:     diffRefTime,
		Request: ElevationRequestV2{UserID: "alice", Publisher: "Contoso Inc"},
	})
	if d.RuleID != "or-rule" {
		t.Fatalf("rule did not match: %+v", d)
	}
	if d.Specificity != WeightPublisher {
		t.Errorf("Specificity = %d, want %d (the matched branch's weight)", d.Specificity, WeightPublisher)
	}
}
