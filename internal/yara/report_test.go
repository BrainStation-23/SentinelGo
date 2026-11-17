package yara

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fullReport() ScanSummary {
	p := "/home/a/locked.db"
	return ScanSummary{ScanID: schID, Trigger: TriggerScheduled, State: ScanPartial, Preset: PresetFull,
		FilesSkipped: 3, Errors: 2,
		SkippedByReason: map[string]int64{"too_large": 2, SkipTimeout: 1},
		ErrorsByReason:  map[string]int64{ErrAccessDenied: 1, ErrLocked: 1},
		EndReason:       EndTimeLimit, BytesScanned: 1 << 20, ThrottledSeconds: 12,
		Scope: &Scope{Roots: []string{"/home"}, Exclusions: []string{}, Limits: ScopeLimits{MaxFileBytes: 1 << 20},
			Rulesets: []ScopeRuleset{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Revision: 3}}},
		ProblemFiles: []ProblemFile{{Path: &p, Reason: ErrLocked, Detail: "The process cannot access the file", Size: 10}},
	}
}

// The contract v1.2 field names the server reads (Compliance-OS #953).
func TestScanSummary_ReportShape(t *testing.T) {
	s := fullReport()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"skipped_by_reason", "errors_by_reason", "end_reason", "bytes_scanned", "throttled_seconds", "scope", "problem_files"} {
		if _, ok := m[k]; !ok {
			t.Errorf("%s missing from %s", k, data)
		}
	}
	scope := m["scope"].(map[string]any)
	for _, k := range []string{"roots", "exclusions", "limits", "rulesets"} {
		if _, ok := scope[k]; !ok {
			t.Errorf("scope.%s missing", k)
		}
	}
	// A v1 summary carries none of them.
	v1, _ := json.Marshal(ScanSummary{ScanID: schID, Trigger: TriggerScheduled, State: ScanCompleted})
	for _, k := range []string{"skipped_by_reason", "end_reason", "scope", "problem_files", "bytes_scanned"} {
		if strings.Contains(string(v1), k) {
			t.Errorf("v1 summary has %s: %s", k, v1)
		}
	}
}

// Validate refuses what the server's _yara_valid_scan_report refuses.
func TestScanSummary_ReportValidateRejects(t *testing.T) {
	long := strings.Repeat("p", MaxPathLen+1)
	bad := "nothex"
	for name, fn := range map[string]func(s *ScanSummary){
		"reason name":  func(s *ScanSummary) { s.SkippedByReason = map[string]int64{"Too-Large": 1} },
		"reason count": func(s *ScanSummary) { s.ErrorsByReason = map[string]int64{ErrLocked: -1} },
		"end reason":   func(s *ScanSummary) { s.EndReason = "crashed" },
		"bytes":        func(s *ScanSummary) { s.BytesScanned = -1 },
		"too many reasons": func(s *ScanSummary) {
			s.SkippedByReason = map[string]int64{}
			for i := range MaxReasons + 1 {
				s.SkippedByReason["r"+strings.Repeat("x", i)] = 1
			}
		},
		"scope root":        func(s *ScanSummary) { s.Scope.Roots = []string{""} },
		"scope ruleset":     func(s *ScanSummary) { s.Scope.Rulesets = []ScopeRuleset{{ID: "local"}} },
		"scope limit":       func(s *ScanSummary) { s.Scope.Limits.MaxScanMinutes = -1 },
		"problem cap":       func(s *ScanSummary) { s.ProblemFiles = make([]ProblemFile, MaxProblemFiles+1) },
		"problem no path":   func(s *ScanSummary) { s.ProblemFiles = []ProblemFile{{Reason: ErrRead}} },
		"problem long path": func(s *ScanSummary) { s.ProblemFiles = []ProblemFile{{Path: &long, Reason: ErrRead}} },
		"problem hash":      func(s *ScanSummary) { s.ProblemFiles = []ProblemFile{{PathHash: &bad, Reason: ErrRead}} },
		"problem reason":    func(s *ScanSummary) { s.ProblemFiles[0].Reason = "" },
		"problem detail":    func(s *ScanSummary) { s.ProblemFiles[0].Detail = strings.Repeat("d", MaxProblemDetail+1) },
	} {
		s := fullReport()
		fn(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

// The status and inventory keep the counts and leave lists and paths out.
func TestScanSummary_Brief(t *testing.T) {
	s := fullReport()
	s.RuleCounts = []RuleCount{{Rule: "r", Files: 1}}
	b := s.Brief()
	if b.Scope != nil || b.ProblemFiles != nil || b.RuleCounts != nil || b.ErrorsByReason == nil || b.EndReason != EndTimeLimit {
		t.Fatalf("brief %+v", b)
	}
	if s.Scope == nil || s.ProblemFiles == nil {
		t.Fatal("Brief changed the summary")
	}
	var nilSum *ScanSummary
	if nilSum.Brief() != nil {
		t.Fatal("Brief of nil")
	}
}
