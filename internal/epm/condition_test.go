package epm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTriAnd(t *testing.T) {
	tests := []struct {
		a, b, want Tri
	}{
		{TriFalse, TriFalse, TriFalse},
		{TriFalse, TriTrue, TriFalse},
		{TriFalse, TriUnknown, TriFalse},
		{TriTrue, TriFalse, TriFalse},
		{TriTrue, TriTrue, TriTrue},
		{TriTrue, TriUnknown, TriUnknown},
		{TriUnknown, TriFalse, TriFalse},
		{TriUnknown, TriTrue, TriUnknown},
		{TriUnknown, TriUnknown, TriUnknown},
	}
	for _, tc := range tests {
		if got := triAnd(tc.a, tc.b); got != tc.want {
			t.Errorf("triAnd(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTriOr(t *testing.T) {
	tests := []struct {
		a, b, want Tri
	}{
		{TriFalse, TriFalse, TriFalse},
		{TriFalse, TriTrue, TriTrue},
		{TriFalse, TriUnknown, TriUnknown},
		{TriTrue, TriFalse, TriTrue},
		{TriTrue, TriTrue, TriTrue},
		{TriTrue, TriUnknown, TriTrue},
		{TriUnknown, TriFalse, TriUnknown},
		{TriUnknown, TriTrue, TriTrue},
		{TriUnknown, TriUnknown, TriUnknown},
	}
	for _, tc := range tests {
		if got := triOr(tc.a, tc.b); got != tc.want {
			t.Errorf("triOr(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTriNot(t *testing.T) {
	tests := []struct{ a, want Tri }{
		{TriFalse, TriTrue},
		{TriTrue, TriFalse},
		{TriUnknown, TriUnknown},
	}
	for _, tc := range tests {
		if got := triNot(tc.a); got != tc.want {
			t.Errorf("triNot(%s) = %s, want %s", tc.a, got, tc.want)
		}
	}
}

func TestTriAnd_CommutativeAndAssociative(t *testing.T) {
	vals := []Tri{TriFalse, TriTrue, TriUnknown}
	for _, a := range vals {
		for _, b := range vals {
			if triAnd(a, b) != triAnd(b, a) {
				t.Errorf("triAnd not commutative for (%s, %s)", a, b)
			}
			for _, c := range vals {
				if triAnd(triAnd(a, b), c) != triAnd(a, triAnd(b, c)) {
					t.Errorf("triAnd not associative for (%s, %s, %s)", a, b, c)
				}
			}
		}
	}
}

// --- Structural caps ---

func chainOfDepth(n int) *Condition {
	// A right-leaning chain of single-child AND branches, n leaves deep.
	var c *Condition = leaf(CondOSType, OpEquals, "linux")
	for i := 0; i < n; i++ {
		c = &Condition{Logic: LogicAnd, Children: []*Condition{c}}
	}
	return c
}

func TestValidateConditionShape_DepthCapRejected(t *testing.T) {
	reg := DefaultMatchers()
	tree := chainOfDepth(MaxConditionDepth + 10)

	nodeCount := 0
	err := validateConditionShape(tree, 1, &nodeCount, reg)
	if err == nil {
		t.Fatal("expected an error for a tree exceeding MaxConditionDepth")
	}
	if !strings.Contains(err.Error(), "depth") {
		t.Errorf("error should mention depth, got: %v", err)
	}
}

func TestValidateConditionShape_DepthWithinCapAccepted(t *testing.T) {
	reg := DefaultMatchers()
	tree := chainOfDepth(MaxConditionDepth - 5)

	nodeCount := 0
	if err := validateConditionShape(tree, 1, &nodeCount, reg); err != nil {
		t.Errorf("tree within MaxConditionDepth was rejected: %v", err)
	}
}

func TestValidateConditionShape_NodeCapRejected(t *testing.T) {
	reg := DefaultMatchers()
	children := make([]*Condition, MaxConditionNodes+10)
	for i := range children {
		children[i] = leaf(CondOSType, OpEquals, "linux")
	}
	tree := &Condition{Logic: LogicOr, Children: children}

	nodeCount := 0
	err := validateConditionShape(tree, 1, &nodeCount, reg)
	if err == nil {
		t.Fatal("expected an error for a tree exceeding MaxConditionNodes")
	}
	if !strings.Contains(err.Error(), "node count") {
		t.Errorf("error should mention node count, got: %v", err)
	}
}

func TestValidateConditionShape_MalformedNodes(t *testing.T) {
	reg := DefaultMatchers()

	tests := []struct {
		name string
		c    *Condition
	}{
		{"both kind and logic set", &Condition{Kind: CondPath, Logic: LogicAnd, Children: []*Condition{leaf(CondOSType, OpEquals, "x")}}},
		{"unknown kind", leaf("nonexistent_kind", OpEquals, "x")},
		{"invalid operator", leaf(CondPath, "not_an_operator", "x")},
		{"invalid regex", leaf(CondCommandLine, OpRegex, "(unclosed")},
		{"NOT with zero children", &Condition{Logic: LogicNot, Children: nil}},
		{"NOT with two children", &Condition{Logic: LogicNot, Children: []*Condition{
			leaf(CondOSType, OpEquals, "linux"), leaf(CondOSType, OpEquals, "windows"),
		}}},
		{"AND with no children", &Condition{Logic: LogicAnd, Children: nil}},
		{"OR with no children", &Condition{Logic: LogicOr, Children: nil}},
		{"invalid logic operator", &Condition{Logic: "xor", Children: []*Condition{leaf(CondOSType, OpEquals, "x")}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nodeCount := 0
			if err := validateConditionShape(tc.c, 1, &nodeCount, reg); err == nil {
				t.Error("expected a validation error, got nil")
			}
		})
	}
}

func TestValidateConditionShape_WildcardAccepted(t *testing.T) {
	reg := DefaultMatchers()
	nodeCount := 0
	if err := validateConditionShape(nil, 1, &nodeCount, reg); err != nil {
		t.Errorf("nil condition (wildcard) should be accepted, got: %v", err)
	}
	if err := validateConditionShape(&Condition{}, 1, &nodeCount, reg); err != nil {
		t.Errorf("zero-value condition (wildcard) should be accepted, got: %v", err)
	}
}

// TestCompile_RejectsRuleNotWholeBundle proves a single malformed rule
// produces a CompileIssue and is excluded, without preventing every other
// rule in the same Compile call from succeeding — a bad rule must not lock
// out the rest of the policy.
func TestCompile_RejectsRuleNotWholeBundle(t *testing.T) {
	good := RuleV2{
		ID: "good", Enabled: true,
		Conditions: leaf(CondOSType, OpEquals, "linux"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	bad := RuleV2{
		ID: "bad", Enabled: true,
		Conditions: leaf("no_such_kind", OpEquals, "x"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}

	set, issues, err := Compile([]RuleV2{good, bad}, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile returned a hard error for a single bad rule: %v", err)
	}
	if len(issues) != 1 || issues[0].RuleID != "bad" {
		t.Fatalf("issues = %+v, want exactly one issue for rule \"bad\"", issues)
	}
	if len(set.rules) != 1 || set.rules[0].ID != "good" {
		t.Fatalf("compiled rules = %+v, want exactly rule \"good\"", set.rules)
	}
}

func TestCompile_TooManyRulesIsHardError(t *testing.T) {
	rules := make([]RuleV2, MaxRulesPerBundle+1)
	for i := range rules {
		rules[i] = RuleV2{ID: "r", Enabled: true, Outcome: Outcome{Verdict: VerdictDeny}}
	}
	if _, _, err := Compile(rules, nil, DefaultMatchers()); err == nil {
		t.Error("expected a hard error when rule count exceeds MaxRulesPerBundle")
	}
}

func TestCompile_NilRegistryIsHardError(t *testing.T) {
	if _, _, err := Compile(nil, nil, nil); err == nil {
		t.Error("expected a hard error for a nil matcher registry")
	}
}

// FuzzConditionUnmarshal proves that decoding arbitrary bytes into a
// Condition, and then structurally validating whatever successfully decodes,
// never panics — regardless of how deeply or how wide an attacker-controlled
// (but JSON-well-formed) policy bundle tries to nest its condition tree.
func FuzzConditionUnmarshal(f *testing.F) {
	f.Add([]byte(`{"kind":"path","op":"eq","value":"C:\\a.exe"}`))
	f.Add([]byte(`{"logic":"and","children":[{"kind":"sha256","value":"abc"}]}`))
	f.Add([]byte(`{"logic":"not","children":[{"kind":"user","op":"eq","value":"x"}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"logic":"and","children":[]}`))

	reg := DefaultMatchers()
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Condition
		if err := json.Unmarshal(data, &c); err != nil {
			return // malformed JSON is expected input, not a bug
		}
		nodeCount := 0
		// Must terminate and must not panic; the return value (match or
		// rejection) is not itself asserted here — validity is what
		// TestValidateConditionShape_* covers.
		_ = validateConditionShape(&c, 1, &nodeCount, reg)
	})
}
