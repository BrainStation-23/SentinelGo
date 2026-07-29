package epm

import (
	"fmt"
	"testing"
	"time"
)

func mustCompile(t *testing.T, rules []RuleV2) *CompiledRuleSet {
	t.Helper()
	set, issues, err := Compile(rules, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("Compile issues: %+v", issues)
	}
	return set
}

// --- Verdict-family Unknown handling ---

func TestEvaluateV2_AllowFamilyDoesNotMatchOnUnknown(t *testing.T) {
	rule := RuleV2{
		ID: "allow-if-encrypted", Enabled: true,
		Conditions: leaf(CondDiskEncryption, OpEquals, "encrypted"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))

	// No ContextProvider wired ⇒ ContextSnapshot{} ⇒ CondDiskEncryption is
	// Unknown ⇒ an allow-family rule must not match: nothing is granted on
	// unverifiable posture.
	d := engine.EvaluateV2(EvalInput{Now: diffRefTime})
	if d.RuleID != "" {
		t.Fatalf("allow-family rule matched on Unknown context: %+v", d)
	}
	if d.Outcome.Verdict != VerdictDeny {
		t.Errorf("default-deny verdict = %s, want deny", d.Outcome.Verdict)
	}
}

func TestEvaluateV2_DenyFamilyMatchesOnUnknown(t *testing.T) {
	rule := RuleV2{
		ID: "deny-unless-encrypted", Enabled: true,
		Conditions: &Condition{Logic: LogicNot, Children: []*Condition{
			leaf(CondDiskEncryption, OpEquals, "encrypted"),
		}},
		Outcome: Outcome{Verdict: VerdictDeny},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))

	d := engine.EvaluateV2(EvalInput{Now: diffRefTime})
	if d.RuleID != "deny-unless-encrypted" {
		t.Fatalf("deny-family rule did not match on Unknown context: %+v", d)
	}
	if len(d.Indeterminate) != 1 || d.Indeterminate[0] != CondDiskEncryption {
		t.Errorf("Indeterminate = %v, want [disk_encryption]", d.Indeterminate)
	}
}

func TestEvaluateV2_OnUnknownOverridesFamilyDefault(t *testing.T) {
	base := RuleV2{
		ID: "signed-required", Enabled: true,
		Conditions: leaf(CondSigned, OpIsTrue, "true"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}

	t.Run(`OnUnknown="match" forces an allow-family rule to match anyway`, func(t *testing.T) {
		r := base
		r.OnUnknown = "match"
		engine := NewEngineWithSet(mustCompile(t, []RuleV2{r}))
		d := engine.EvaluateV2(EvalInput{Now: diffRefTime}) // Publisher empty ⇒ CondSigned Unknown
		if d.RuleID != "signed-required" {
			t.Errorf("OnUnknown=match did not force a match: %+v", d)
		}
	})

	denyBase := RuleV2{
		ID: "block-unless-known-safe", Enabled: true,
		Conditions: leaf(CondCompliance, OpEquals, "compliant"),
		Outcome:    Outcome{Verdict: VerdictDeny},
	}
	t.Run(`OnUnknown="skip" forces a deny-family rule to NOT match`, func(t *testing.T) {
		r := denyBase
		r.OnUnknown = "skip"
		engine := NewEngineWithSet(mustCompile(t, []RuleV2{r}))
		d := engine.EvaluateV2(EvalInput{Now: diffRefTime})
		if d.RuleID != "" {
			t.Errorf("OnUnknown=skip did not suppress the deny-family match: %+v", d)
		}
	})
}

// --- Verdict families beyond allow/deny ---

func TestEvaluateV2_AuditOnlyVerdictProjectsToAllowedLegacy(t *testing.T) {
	rule := RuleV2{
		ID: "audit-only", Enabled: true,
		Conditions: leaf(CondPublisher, OpEquals, "Contoso Inc"),
		Outcome:    Outcome{Verdict: VerdictAuditOnly, Reason: "observed"},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))

	d := engine.EvaluateV2(EvalInput{Request: ElevationRequestV2{Publisher: "Contoso Inc"}, Now: diffRefTime})
	if d.Outcome.Verdict != VerdictAuditOnly {
		t.Fatalf("verdict = %s, want audit_only", d.Outcome.Verdict)
	}
	// Legacy() treats audit_only as "allowed" — permit, but recorded as a
	// would-deny by the caller inspecting the richer v2 Outcome.
	legacy := d.Legacy()
	if !legacy.Allowed {
		t.Error("audit_only should project to Allowed=true in the v1 legacy response")
	}
}

func TestEvaluateV2_MonitorVerdictIsDenyFamilyAndProjectsToDenied(t *testing.T) {
	rule := RuleV2{
		ID: "monitor-only", Enabled: true,
		Conditions: leaf(CondPublisher, OpEquals, "Contoso Inc"),
		Outcome:    Outcome{Verdict: VerdictMonitor},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))

	d := engine.EvaluateV2(EvalInput{Request: ElevationRequestV2{Publisher: "Contoso Inc"}, Now: diffRefTime})
	if d.Outcome.Verdict != VerdictMonitor {
		t.Fatalf("verdict = %s, want monitor", d.Outcome.Verdict)
	}
	if legacy := d.Legacy(); legacy.Allowed {
		t.Error("monitor should project to Allowed=false in the v1 legacy response — no elevation happens")
	}
}

func TestVerdict_FamilyClassification(t *testing.T) {
	allowFamily := []Verdict{VerdictAllow, VerdictAuditOnly, VerdictPrompt, VerdictRequireJustification, VerdictRequireApproval}
	denyFamily := []Verdict{VerdictDeny, VerdictMonitor}

	for _, v := range allowFamily {
		if !v.IsAllowFamily() || v.IsDenyFamily() {
			t.Errorf("%s: want IsAllowFamily=true, IsDenyFamily=false", v)
		}
	}
	for _, v := range denyFamily {
		if v.IsAllowFamily() || !v.IsDenyFamily() {
			t.Errorf("%s: want IsAllowFamily=false, IsDenyFamily=true", v)
		}
	}
}

func TestOutcome_EffectiveFallbackDefaultsToDeny(t *testing.T) {
	if got := (Outcome{}).EffectiveFallback(); got != VerdictDeny {
		t.Errorf("EffectiveFallback() with no override = %s, want deny", got)
	}
	if got := (Outcome{FallbackVerdict: VerdictAllow}).EffectiveFallback(); got != VerdictAllow {
		t.Errorf("EffectiveFallback() with an explicit override = %s, want allow", got)
	}
}

// --- Constraints pass-through ---

func TestEvaluateV2_ConstraintsPassThroughUnmodified(t *testing.T) {
	want := Constraints{
		TokenType: TokenSystem, ChildProcess: ChildDeny,
		ChildAllowed: []string{"C:/allowed/*"}, WorkingDir: "C:/work",
	}
	rule := RuleV2{
		ID: "constrained", Enabled: true,
		Conditions: leaf(CondPath, OpEquals, "C:/apps/tool.exe"),
		Outcome:    Outcome{Verdict: VerdictAllow, Constraints: want},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))
	d := engine.EvaluateV2(EvalInput{Request: ElevationRequestV2{AppPath: "C:/apps/tool.exe"}, Now: diffRefTime})

	got := d.Outcome.Constraints
	if got.TokenType != want.TokenType || got.ChildProcess != want.ChildProcess ||
		got.WorkingDir != want.WorkingDir || len(got.ChildAllowed) != 1 || got.ChildAllowed[0] != want.ChildAllowed[0] {
		t.Errorf("Constraints = %+v, want %+v", got, want)
	}
}

func TestConstraints_EffectiveTokenTypeDefaultsToElevated(t *testing.T) {
	if got := (Constraints{}).EffectiveTokenType(); got != TokenElevated {
		t.Errorf("EffectiveTokenType() with no override = %s, want elevated", got)
	}
	if got := (Constraints{TokenType: TokenSystem}).EffectiveTokenType(); got != TokenSystem {
		t.Errorf("EffectiveTokenType() with an explicit override = %s, want system", got)
	}
}

// --- ContextProvider wiring ---

type fakeContextProvider struct{ snap ContextSnapshot }

func (f fakeContextProvider) Snapshot() ContextSnapshot { return f.snap }

func TestEvaluateV2_UsesWiredContextProviderWhenCallerSuppliesNone(t *testing.T) {
	now := diffRefTime
	rule := RuleV2{
		ID: "vpn-required", Enabled: true,
		Conditions: leaf(CondVPNActive, OpIsTrue, "true"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	provider := fakeContextProvider{snap: ContextSnapshot{
		VPNActive: TriTrue,
		Sources:   map[string]SourceState{"network": {CollectedAt: now, OK: true}},
	}}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}), WithContextProvider(provider))

	d := engine.EvaluateV2(EvalInput{Now: now}) // no Context supplied by the caller
	if d.RuleID != "vpn-required" {
		t.Fatalf("expected the wired ContextProvider's snapshot to be used: %+v", d)
	}
}

func TestEvaluateV2_CallerSuppliedContextTakesPrecedenceOverProvider(t *testing.T) {
	now := diffRefTime
	rule := RuleV2{
		ID: "vpn-required", Enabled: true,
		Conditions: leaf(CondVPNActive, OpIsTrue, "true"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	provider := fakeContextProvider{snap: ContextSnapshot{
		VPNActive: TriTrue,
		Sources:   map[string]SourceState{"network": {CollectedAt: now, OK: true}},
	}}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}), WithContextProvider(provider))

	callerCtx := ContextSnapshot{
		VPNActive: TriFalse,
		Sources:   map[string]SourceState{"network": {CollectedAt: now, OK: true}},
	}
	d := engine.EvaluateV2(EvalInput{Now: now, Context: callerCtx})
	if d.RuleID != "" {
		t.Fatalf("caller-supplied Context (VPN inactive) should have been used, not the provider's: %+v", d)
	}
}

// --- Explain trace ---

func TestEvaluateV2_ExplainOnlyPopulatedWhenRequested(t *testing.T) {
	rule := RuleV2{
		ID: "explainable", Enabled: true,
		Conditions: leaf(CondPath, OpEquals, "C:/apps/tool.exe"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule}))
	req := ElevationRequestV2{AppPath: "C:/apps/tool.exe"}

	without := engine.EvaluateV2(EvalInput{Request: req, Now: diffRefTime})
	if len(without.Explain) != 0 {
		t.Errorf("Explain populated without Explain:true: %+v", without.Explain)
	}

	with := engine.EvaluateV2(EvalInput{Request: req, Now: diffRefTime, Explain: true})
	if len(with.Explain) == 0 {
		t.Error("Explain empty despite Explain:true")
	}
}

// --- Swap ---

func TestEngine_SwapHotReplacesPolicy(t *testing.T) {
	rule1 := RuleV2{ID: "r1", Enabled: true, Conditions: leaf(CondUser, OpEquals, "alice"), Outcome: Outcome{Verdict: VerdictAllow}}
	engine := NewEngineWithSet(mustCompile(t, []RuleV2{rule1}))

	req := EvalInput{Request: ElevationRequestV2{UserID: "alice"}, Now: diffRefTime}
	if d := engine.EvaluateV2(req); d.RuleID != "r1" {
		t.Fatalf("before swap: %+v", d)
	}

	rule2 := RuleV2{ID: "r2", Enabled: true, Conditions: leaf(CondUser, OpEquals, "alice"), Outcome: Outcome{Verdict: VerdictDeny}}
	engine.Swap(mustCompile(t, []RuleV2{rule2}))

	d := engine.EvaluateV2(req)
	if d.RuleID != "r2" {
		t.Fatalf("after swap: %+v, want rule r2 to be the only rule in effect", d)
	}
}

// --- Rule group folding ---

func TestCompile_RuleGroupFoldsConditionsAndPriority(t *testing.T) {
	group := RuleGroup{
		ID: "g1", Enabled: true, Priority: 100,
		Conditions: leaf(CondUser, OpEquals, "alice"),
	}
	member := RuleV2{
		ID: "member", GroupID: "g1", Enabled: true, Priority: 5,
		Conditions: leaf(CondPath, OpEquals, "C:/apps/tool.exe"),
		Outcome:    Outcome{Verdict: VerdictAllow},
	}
	set2, issues, err := Compile([]RuleV2{member}, []RuleGroup{group}, DefaultMatchers())
	if err != nil || len(issues) != 0 {
		t.Fatalf("Compile: err=%v issues=%v", err, issues)
	}
	if len(set2.rules) != 1 {
		t.Fatalf("expected exactly one compiled rule, got %d", len(set2.rules))
	}
	cr := set2.rules[0]
	if cr.Priority != 105 {
		t.Errorf("Priority = %d, want 105 (5 member + 100 group)", cr.Priority)
	}

	engine := NewEngineWithSet(set2)
	// Matches the group's user condition but not the member's path — must not match.
	d := engine.EvaluateV2(EvalInput{Request: ElevationRequestV2{UserID: "alice", AppPath: "C:/apps/other.exe"}, Now: diffRefTime})
	if d.RuleID != "" {
		t.Errorf("rule matched despite failing the group-folded path condition: %+v", d)
	}
	// Matches both.
	d = engine.EvaluateV2(EvalInput{Request: ElevationRequestV2{UserID: "alice", AppPath: "C:/apps/tool.exe"}, Now: diffRefTime})
	if d.RuleID != "member" {
		t.Errorf("rule did not match despite satisfying both group and member conditions: %+v", d)
	}
}

func TestCompile_UnknownGroupReferenceIsCompileIssue(t *testing.T) {
	member := RuleV2{ID: "orphan", GroupID: "no-such-group", Enabled: true, Outcome: Outcome{Verdict: VerdictAllow}}
	set, issues, err := Compile([]RuleV2{member}, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(issues) != 1 || issues[0].RuleID != "orphan" {
		t.Fatalf("issues = %+v, want one issue for rule \"orphan\"", issues)
	}
	if len(set.rules) != 0 {
		t.Errorf("expected the orphaned rule to be excluded, got %d compiled rules", len(set.rules))
	}
}

// --- Benchmark ---

func BenchmarkEvaluate(b *testing.B) {
	rules := make([]PolicyRule, 5000)
	for i := range rules {
		rules[i] = PolicyRule{
			ID:       fmt.Sprintf("rule-%d", i),
			AppPath:  fmt.Sprintf(`C:\apps\app%d\tool.exe`, i),
			Decision: DecisionAllow,
			Priority: i % 10,
		}
	}
	engine := NewEngine(rules)
	req := ElevationRequest{
		AppPath: `C:\apps\app2500\tool.exe`,
		AppHash: "abc123",
		Now:     time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(req)
	}
}
