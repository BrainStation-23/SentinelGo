package epm

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestEngine_DefaultDenyWhenNoRules(t *testing.T) {
	e := NewEngine(nil)
	resp := e.Evaluate(ElevationRequest{UserID: "alice", AppPath: `C:\apps\tool.exe`})
	if resp.Allowed {
		t.Fatal("expected deny when no rules exist")
	}
}

func TestEngine_HashBeatsEverythingElse(t *testing.T) {
	rules := []PolicyRule{
		{ID: "path-rule", AppPath: `C:\apps\tool.exe`, Decision: DecisionDeny, Priority: 100},
		{ID: "hash-rule", AppHash: "abc123", Decision: DecisionAllow, Priority: 0},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `C:\apps\tool.exe`, AppHash: "abc123"})
	if !resp.Allowed || resp.PolicyID != "hash-rule" {
		t.Fatalf("expected hash-rule to win, got %+v", resp)
	}
}

func TestEngine_PublisherBeatsPath(t *testing.T) {
	rules := []PolicyRule{
		{ID: "path-rule", AppPath: `/usr/bin/tool`, Decision: DecisionDeny},
		{ID: "publisher-rule", Publisher: "Acme Inc", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/usr/bin/tool`, Publisher: "Acme Inc"})
	if !resp.Allowed || resp.PolicyID != "publisher-rule" {
		t.Fatalf("expected publisher-rule to win, got %+v", resp)
	}
}

func TestEngine_ExactPathBeatsGlob(t *testing.T) {
	rules := []PolicyRule{
		{ID: "glob-rule", AppPath: `/opt/*/tool`, Decision: DecisionDeny},
		{ID: "exact-rule", AppPath: `/opt/acme/tool`, Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/opt/acme/tool`})
	if !resp.Allowed || resp.PolicyID != "exact-rule" {
		t.Fatalf("expected exact-rule to win, got %+v", resp)
	}
}

func TestEngine_GlobMatchesPattern(t *testing.T) {
	rules := []PolicyRule{
		{ID: "glob-rule", AppPath: `/opt/*/tool`, Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/opt/acme/tool`})
	if !resp.Allowed || resp.PolicyID != "glob-rule" {
		t.Fatalf("expected glob-rule to match, got %+v", resp)
	}

	respNoMatch := e.Evaluate(ElevationRequest{AppPath: `/opt/acme/sub/tool`})
	if respNoMatch.Allowed {
		t.Fatalf("glob should not match nested path segments, got %+v", respNoMatch)
	}
}

func TestEngine_WildcardRuleMatchesAnyApp(t *testing.T) {
	rules := []PolicyRule{
		{ID: "wildcard-rule", UserID: "alice", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{UserID: "alice", AppPath: "/anything"})
	if !resp.Allowed || resp.PolicyID != "wildcard-rule" {
		t.Fatalf("expected wildcard-rule to match any app for alice, got %+v", resp)
	}

	respOther := e.Evaluate(ElevationRequest{UserID: "bob", AppPath: "/anything"})
	if respOther.Allowed {
		t.Fatalf("wildcard-rule is scoped to alice, must not match bob: %+v", respOther)
	}
}

func TestEngine_ExpiredRuleIsSkipped(t *testing.T) {
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rules := []PolicyRule{
		{ID: "expired-rule", AppPath: "/tool", Decision: DecisionAllow, ExpiresAt: past},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: "/tool", Now: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})
	if resp.Allowed {
		t.Fatalf("expired rule must be skipped, got %+v", resp)
	}
}

func TestEngine_UnexpiredRuleStillApplies(t *testing.T) {
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	rules := []PolicyRule{
		{ID: "future-rule", AppPath: "/tool", Decision: DecisionAllow, ExpiresAt: future},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: "/tool", Now: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})
	if !resp.Allowed {
		t.Fatalf("unexpired rule should apply, got %+v", resp)
	}
}

func TestEngine_HigherPriorityWinsWithinSameTier(t *testing.T) {
	rules := []PolicyRule{
		{ID: "low-priority", AppPath: "/tool", Decision: DecisionAllow, Priority: 1},
		{ID: "high-priority", AppPath: "/tool", Decision: DecisionDeny, Priority: 10},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: "/tool"})
	if resp.Allowed || resp.PolicyID != "high-priority" {
		t.Fatalf("expected high-priority rule to win, got %+v", resp)
	}
}

func TestPolicyRule_JSONRoundTrip_EmptyExpiresAt(t *testing.T) {
	original := PolicyRule{ID: "r1", AppPath: "/tool", Decision: DecisionAllow, Priority: 5}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded PolicyRule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !decoded.ExpiresAt.IsZero() {
		t.Errorf("expected zero ExpiresAt, got %v", decoded.ExpiresAt)
	}
	if decoded.ID != original.ID || decoded.AppPath != original.AppPath {
		t.Errorf("round trip mismatch: got %+v, want %+v", decoded, original)
	}
}

func TestPolicyRule_UnmarshalJSON_MissingExpiresAtField(t *testing.T) {
	raw := []byte(`{"id":"r2","app_path":"/tool","decision":"allow","priority":1}`)
	var rule PolicyRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !rule.ExpiresAt.IsZero() {
		t.Errorf("expected zero ExpiresAt when field absent, got %v", rule.ExpiresAt)
	}
}

func TestPolicyRule_UnmarshalJSON_InvalidExpiresAt(t *testing.T) {
	raw := []byte(`{"id":"r3","expires_at":"not-a-date"}`)
	var rule PolicyRule
	if err := json.Unmarshal(raw, &rule); err == nil {
		t.Fatal("expected error for invalid expires_at")
	}
}

func TestPolicyRule_JSONRoundTrip_WithExpiresAt(t *testing.T) {
	expires := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
	original := PolicyRule{ID: "r4", Publisher: "Acme", Decision: DecisionDeny, ExpiresAt: expires}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded PolicyRule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !decoded.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, expires)
	}
}

func TestEngine_ScriptHashRuleMatchesInterpreterAndScript(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `C:\Windows\System32\msiexec.exe`, ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `C:\Windows\System32\msiexec.exe`,
		ScriptPath: `C:\Users\jsmith\Downloads\tool.msi`,
		ScriptHash: "deadbeef",
	})
	if !resp.Allowed || resp.PolicyID != "script-rule" {
		t.Fatalf("expected script-rule to match, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleRequiresInterpreterPathMatch(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `C:\Windows\System32\msiexec.exe`, ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `C:\Windows\System32\powershell.exe`,
		ScriptHash: "deadbeef",
	})
	if resp.Allowed {
		t.Fatalf("rule scoped to msiexec.exe must not match a different interpreter, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleRequiresScriptHashMatch(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/usr/bin/dpkg`, ScriptHash: "wrong-hash"})
	if resp.Allowed {
		t.Fatalf("mismatched script hash must not match, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleWithAllowedArgsExactMatch(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef", AllowedArgs: "-i /tmp/tool.deb", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `/usr/bin/dpkg`,
		ScriptHash: "deadbeef",
		ActualArgs: "  -i /tmp/tool.deb  ", // request args are trimmed before comparison
	})
	if !resp.Allowed || resp.PolicyID != "script-rule" {
		t.Fatalf("expected trimmed args to match AllowedArgs, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleWithAllowedArgsMismatch(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef", AllowedArgs: "-i /tmp/tool.deb", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `/usr/bin/dpkg`,
		ScriptHash: "deadbeef",
		ActualArgs: "-i /tmp/other.deb",
	})
	if resp.Allowed {
		t.Fatalf("mismatched args must not match AllowedArgs, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleWithoutAllowedArgsMatchesAnyArgs(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `/usr/bin/dpkg`,
		ScriptHash: "deadbeef",
		ActualArgs: "-i /tmp/anything-at-all.deb",
	})
	if !resp.Allowed {
		t.Fatalf("rule without AllowedArgs should match any args, got %+v", resp)
	}
}

func TestEngine_ScriptHashRuleMissingAppPathNeverMatches(t *testing.T) {
	rules := []PolicyRule{
		{ID: "script-rule", ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef"})
	if resp.Allowed {
		t.Fatalf("a ScriptHash rule with no AppPath must fail closed, got %+v", resp)
	}
}

func TestEngine_ScriptHashBeatsPathAndPublisherRules(t *testing.T) {
	rules := []PolicyRule{
		{ID: "deny-path", AppPath: `/usr/bin/dpkg`, Decision: DecisionDeny, Priority: 100},
		{ID: "deny-publisher", Publisher: "Debian", Decision: DecisionDeny, Priority: 100},
		{ID: "script-rule", AppPath: `/usr/bin/dpkg`, ScriptHash: "deadbeef", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:    `/usr/bin/dpkg`,
		Publisher:  "Debian",
		ScriptHash: "deadbeef",
	})
	if !resp.Allowed || resp.PolicyID != "script-rule" {
		t.Fatalf("expected script-rule (tierHash) to win over path/publisher rules, got %+v", resp)
	}
}

func TestEngine_ExistingRulesUnaffectedByNewFields(t *testing.T) {
	// Regression: rules using only pre-existing fields must evaluate
	// identically now that ScriptHash/AllowedArgs/AllowedServiceName exist.
	rules := []PolicyRule{
		{ID: "hash-rule", AppHash: "abc123", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `/usr/bin/tool`, AppHash: "abc123"})
	if !resp.Allowed || resp.PolicyID != "hash-rule" {
		t.Fatalf("expected hash-rule to still match as before, got %+v", resp)
	}
}

func TestEngine_AllowedServiceNameStacksOnPathExactTier(t *testing.T) {
	rules := []PolicyRule{
		{ID: "svc-rule", AppPath: `C:\Windows\System32\sc.exe`, AllowedServiceName: "w3svc", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:              `C:\Windows\System32\sc.exe`,
		RequestedServiceName: "w3svc",
	})
	if !resp.Allowed || resp.PolicyID != "svc-rule" {
		t.Fatalf("expected svc-rule to match when service name matches, got %+v", resp)
	}
}

func TestEngine_AllowedServiceNameMismatchDenies(t *testing.T) {
	rules := []PolicyRule{
		{ID: "svc-rule", AppPath: `C:\Windows\System32\sc.exe`, AllowedServiceName: "w3svc", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:              `C:\Windows\System32\sc.exe`,
		RequestedServiceName: "other-service",
	})
	if resp.Allowed {
		t.Fatalf("expected deny when requested service name does not match, got %+v", resp)
	}
}

func TestEngine_AllowedServiceNameRequiredButRequestHasNone(t *testing.T) {
	rules := []PolicyRule{
		{ID: "svc-rule", AppPath: `C:\Windows\System32\sc.exe`, AllowedServiceName: "w3svc", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{AppPath: `C:\Windows\System32\sc.exe`})
	if resp.Allowed {
		t.Fatalf("expected deny when no service name could be extracted (safer to deny), got %+v", resp)
	}
}

func TestEngine_AllowedServiceNameStacksOnWildcardTier(t *testing.T) {
	rules := []PolicyRule{
		{ID: "wildcard-svc-rule", UserID: "alice", AllowedServiceName: "nginx", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{UserID: "alice", RequestedServiceName: "nginx"})
	if !resp.Allowed || resp.PolicyID != "wildcard-svc-rule" {
		t.Fatalf("expected wildcard rule with matching service name to match, got %+v", resp)
	}

	respMismatch := e.Evaluate(ElevationRequest{UserID: "alice", RequestedServiceName: "postgresql"})
	if respMismatch.Allowed {
		t.Fatalf("wildcard rule scoped to nginx must not match a different service, got %+v", respMismatch)
	}
}

func TestEngine_AllowedServiceNameCasingIsOSAware(t *testing.T) {
	rules := []PolicyRule{
		{ID: "svc-rule", AppPath: "/usr/bin/systemctl", AllowedServiceName: "W3SVC", Decision: DecisionAllow},
	}
	e := NewEngine(rules)
	resp := e.Evaluate(ElevationRequest{
		AppPath:              "/usr/bin/systemctl",
		RequestedServiceName: "w3svc",
	})

	if runtime.GOOS == "windows" {
		if !resp.Allowed {
			t.Fatalf("expected case-insensitive service name match on windows, got %+v", resp)
		}
	} else if resp.Allowed {
		t.Fatalf("expected exact-case service name comparison on %s, got %+v", runtime.GOOS, resp)
	}
}
