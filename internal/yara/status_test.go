package yara

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStatus_EncodeShape(t *testing.T) {
	started := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	s := Status{
		AppliedVersion: "v-abc", AgentVersion: "4.1.0", EngineVersion: "0.9.0", State: StateOK,
		Rulesets: []RulesetStatus{{ID: rsID, Revision: 3, CompiledRules: 41,
			SkippedRules: []SkippedRule{{Rule: "APT_X", Line: 12, Reason: "unsupported_module:pe"}}}},
		LastScan: &ScanSummary{ScanID: schID, Trigger: TriggerScheduled, Preset: PresetQuick,
			StartedAt: started, FinishedAt: started.Add(time.Minute), State: ScanCompleted,
			FilesScanned: 10, FilesSkipped: 2, Matches: 1},
	}
	data, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"applied_version": "v-abc", "agent_version": "4.1.0", "engine_version": "0.9.0", "state": "ok",
		"rulesets": []any{map[string]any{"id": rsID, "revision": 3.0, "compiled_rules": 41.0,
			"skipped_rules": []any{map[string]any{"rule": "APT_X", "line": 12.0, "reason": "unsupported_module:pe"}}}},
		"last_scan": map[string]any{"scan_id": schID, "trigger": "scheduled", "preset": "quick",
			"started_at": "2026-11-10T09:00:00Z", "finished_at": "2026-11-10T09:01:00Z", "state": "completed",
			"files_scanned": 10.0, "files_skipped": 2.0, "errors": 0.0, "matches": 1.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status JSON\n%s\nwant\n%v", data, want)
	}
	var back Status
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, s) {
		t.Fatalf("round trip:\n%+v\nwant\n%+v", back, s)
	}
}

func TestStatus_EmptyListsAreArrays(t *testing.T) {
	data, err := Status{State: StateDisabled}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"rulesets":[]`) || !strings.Contains(string(data), `"last_scan":null`) {
		t.Fatalf("status = %s", data)
	}
}

func TestStatus_Caps(t *testing.T) {
	var rs []RulesetStatus
	for i := range MaxRulesets + 5 {
		r := RulesetStatus{ID: fmt.Sprintf("6f1c2a40-1111-4c3b-9a55-%012d", i), Revision: 1}
		for j := range MaxSkippedRules + 20 {
			r.SkippedRules = append(r.SkippedRules, SkippedRule{
				Rule: strings.Repeat("r", 300), Line: j, Reason: strings.Repeat("é", 300),
			})
		}
		rs = append(rs, r)
	}
	s := Status{AppliedVersion: strings.Repeat("v", 500), AgentVersion: strings.Repeat("a", 100), State: StateOK, Rulesets: rs}
	data, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxStatusBytes {
		t.Fatalf("status is %d bytes, over %d", len(data), MaxStatusBytes)
	}
	var got Status
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rulesets) == 0 || len(got.Rulesets) > MaxRulesets {
		t.Fatalf("%d rulesets", len(got.Rulesets))
	}
	if len(got.AppliedVersion) > MaxVersionLen || len(got.AgentVersion) > MaxAgentVerLen {
		t.Errorf("versions not cut: %d, %d", len(got.AppliedVersion), len(got.AgentVersion))
	}
	for _, r := range got.Rulesets {
		if len(r.SkippedRules) > MaxSkippedRules {
			t.Fatalf("%d skipped rules", len(r.SkippedRules))
		}
		for _, k := range r.SkippedRules {
			if len(k.Rule) > MaxRuleLen || len(k.Reason) > MaxErrorLen {
				t.Fatalf("skipped rule not cut: %d, %d", len(k.Rule), len(k.Reason))
			}
			if !strings.HasPrefix(strings.Repeat("é", 300), k.Reason) {
				t.Fatal("reason cut inside a UTF-8 sequence")
			}
		}
	}
	// The caller's status is untouched.
	if len(s.Rulesets) != MaxRulesets+5 || len(s.Rulesets[0].SkippedRules) != MaxSkippedRules+20 ||
		len(s.Rulesets[0].SkippedRules[0].Rule) != 300 {
		t.Error("Encode modified its input")
	}
}

func TestTruncate(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"aé", 2, "a"}, // é is 2 bytes; don't split it
		{"日本", 4, "日"},
		{"", 0, ""},
	} {
		if got := truncate(tc.in, tc.n); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
