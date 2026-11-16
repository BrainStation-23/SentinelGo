package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

var fullMode = yara.Evidence{PathMode: yara.PathModeFull}

// Errors come first, the sample stops at 200 (an error replaces a skip),
// and expected skips are never problem files.
func TestProblem_ErrorsFirstAndCapped(t *testing.T) {
	s := testScan(yara.TriggerScheduled, fullMode, nil)
	s.Problem("/x/unchanged", "unchanged", "", 0, false)
	s.Problem("/x/link", "link", "", 0, false)
	for i := range yara.MaxProblemFiles {
		s.Problem(fmt.Sprintf("/x/big%d", i), "too_large", "", 9, false)
	}
	s.Problem("/x/locked", yara.ErrLocked, "in use", 0, true)
	p := s.Progress().Coverage.Problems
	if len(p) != yara.MaxProblemFiles || p[0].Reason != yara.ErrLocked || *p[0].Path != "/x/locked" {
		t.Fatalf("%d problems, first %+v", len(p), p[0])
	}
	for _, f := range p {
		if f.Reason == "unchanged" || f.Reason == "link" {
			t.Fatalf("expected skip in the sample: %+v", f)
		}
	}
	if last := p[len(p)-1]; *last.Path != fmt.Sprintf("/x/big%d", yara.MaxProblemFiles-2) {
		t.Errorf("the error didn't replace the last skip: %+v", last)
	}
	s.Problem("/x/another", "too_large", "", 1, false)
	if got := s.Progress().Coverage.Problems; len(got) != yara.MaxProblemFiles {
		t.Errorf("a skip past the cap was added: %d", len(got))
	}
}

// Hashed path mode: problem files carry the hash and extension only.
func TestProblem_HashedPath(t *testing.T) {
	s := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeHashed}, nil)
	s.Problem(`C:\Users\a\Secret.DOCX`, yara.ErrAccessDenied, "Access is denied.", 0, true)
	p := s.Progress().Coverage.Problems[0]
	if p.Path != nil || p.PathHash == nil || *p.PathHash != HashPath(`C:\Users\a\Secret.DOCX`) || p.FileExt != "docx" {
		t.Fatalf("problem %+v", p)
	}
}

// The coverage goes through a checkpoint (JSON in the state file) and the
// resumed scan adds to it.
func TestCoverage_SurvivesCheckpoint(t *testing.T) {
	s := testScan(yara.TriggerScheduled, fullMode, nil)
	s.Skip("too_large", 2)
	s.Fail(yara.ErrLocked, 1)
	s.AddBytes(100)
	s.AddThrottled(3 * time.Second)
	s.Problem("/x/a", "too_large", "", 5, false)
	s.Problem("/x/b", yara.ErrLocked, "busy", 0, true)
	data, err := json.Marshal(s.Progress())
	if err != nil {
		t.Fatal(err)
	}
	var p Progress
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	r := testScan(yara.TriggerScheduled, fullMode, nil)
	r.Restore(time.Time{}, p)
	r.Skip("too_large", 1)
	r.Problem("/x/c", yara.ErrRead, "", 0, true)
	sum := r.SummaryBody(yara.ScanCompleted, 1, 3, 2)
	if sum.SkippedByReason["too_large"] != 3 || sum.ErrorsByReason[yara.ErrLocked] != 1 ||
		sum.BytesScanned != 100 || sum.ThrottledSeconds != 3 {
		t.Fatalf("summary %+v", sum)
	}
	var order []string
	for _, f := range sum.ProblemFiles {
		order = append(order, *f.Path)
	}
	if strings.Join(order, ",") != "/x/b,/x/c,/x/a" {
		t.Errorf("problem order %v, want errors first, in order", order)
	}
	// A completed scan has no end reason, even if one was set.
	r.SetEndReason(yara.EndShutdown)
	if r.SummaryBody(yara.ScanCompleted, 0, 0, 0).EndReason != "" {
		t.Error("end_reason on a completed scan")
	}
	if r.SummaryBody(yara.ScanCancelled, 0, 0, 0).EndReason != yara.EndShutdown {
		t.Error("end_reason lost")
	}
}

// Over 32 KB, problem files go first; the rule counts stay whole.
func TestSummary_FitsProblemsFirst(t *testing.T) {
	s := testScan(yara.TriggerOnDemand, fullMode, nil)
	for i := range yara.MaxProblemFiles {
		s.Problem(fmt.Sprintf("/x/%04d/%s", i, strings.Repeat("d", 300)), yara.ErrRead, strings.Repeat("e", 150), 0, true)
	}
	if _, err := s.Matches(result("/f", hit("r1"), hit("r2"))); err != nil {
		t.Fatal(err)
	}
	ev := s.Summary(yara.ScanCompleted, 1, 0, yara.MaxProblemFiles)
	data, _ := json.Marshal(ev)
	n := len(ev.Summary.ProblemFiles)
	if len(data) > yara.MaxSummaryBytes+200 || n == 0 || n == yara.MaxProblemFiles {
		t.Fatalf("%d bytes with %d problem files", len(data), n)
	}
	if len(ev.Summary.RuleCounts) != 2 || ev.Summary.RuleCountsTruncated {
		t.Errorf("rule counts cut: %+v", ev.Summary.RuleCounts)
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The scope lists the scan's folders, limits and rulesets; hashed mode
// hashes the folders.
func TestSetScope(t *testing.T) {
	l := yara.Limits{MaxFileBytes: 7, PerFileTimeoutMS: 8, MaxScanMinutes: 9, MaxFilesPerScan: 10}
	rs := []yara.Ruleset{{ID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", Revision: 2}, {ID: "local", Revision: 1}}
	s := testScan(yara.TriggerScheduled, fullMode, nil)
	s.SetScope([]string{"/home", ""}, nil, l, rs)
	sum := s.SummaryBody(yara.ScanCompleted, 0, 0, 0)
	sc := sum.Scope
	if len(sc.Roots) != 1 || sc.Roots[0] != "/home" || sc.Exclusions == nil || len(sc.Rulesets) != 1 ||
		sc.Rulesets[0].ID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || sc.Limits.MaxFilesPerScan != 10 {
		t.Fatalf("scope %+v", sc)
	}
	h := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeHashed}, nil)
	h.SetScope([]string{"/home"}, []string{"/home/tmp"}, l, rs)
	if hs := h.SummaryBody(yara.ScanCompleted, 0, 0, 0).Scope; hs.Roots[0] != HashPath("/home") || hs.Exclusions[0] != HashPath("/home/tmp") {
		t.Fatalf("hashed scope %+v", hs)
	}
}

// A checkpoint saved in full path mode, resumed in hashed mode, sends no
// plain path.
func TestCoverage_RestoreAppliesHashedMode(t *testing.T) {
	full := testScan(yara.TriggerScheduled, fullMode, nil)
	full.Problem("/home/a/secret.pdf", yara.ErrLocked, "busy", 0, true)
	h := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeHashed}, nil)
	h.Restore(time.Time{}, full.Progress())
	p := h.SummaryBody(yara.ScanCompleted, 0, 0, 1).ProblemFiles
	if len(p) != 1 || p[0].Path != nil || p[0].PathHash == nil || *p[0].PathHash != HashPath("/home/a/secret.pdf") || p[0].FileExt != "pdf" {
		t.Fatalf("restored problem %+v", p)
	}
}

// A scope too big for the summary is cut to its budget, and the summary,
// with rule counts cut near the boundary, stays within 32 KB.
func TestSummary_LargeScopeFits(t *testing.T) {
	excl := make([]string, yara.MaxScopeExclusions)
	for i := range excl {
		excl[i] = fmt.Sprintf("/data/%03d/%s", i, strings.Repeat("x", 180))
	}
	s := testScan(yara.TriggerOnDemand, fullMode, nil)
	s.SetScope([]string{"/data"}, excl, yara.Limits{}, nil)
	for i := range yara.MaxRuleCounts {
		if _, err := s.Matches(result("/f", hit(fmt.Sprintf("rule%03d", i)))); err != nil {
			t.Fatal(err)
		}
	}
	sum := s.SummaryBody(yara.ScanCompleted, 1, 0, 0)
	data, _ := json.Marshal(sum)
	sc, _ := json.Marshal(sum.Scope)
	if len(data) > yara.MaxSummaryBytes || len(sc) > scopeBudget || len(sum.Scope.Exclusions) == 0 || len(sum.Scope.Roots) != 1 {
		t.Fatalf("summary %d bytes, scope %d bytes, %d exclusions", len(data), len(sc), len(sum.Scope.Exclusions))
	}
	if !sum.RuleCountsTruncated || len(sum.RuleCounts) == 0 {
		t.Fatalf("rule counts %d, truncated %v", len(sum.RuleCounts), sum.RuleCountsTruncated)
	}
	if err := sum.Validate(); err != nil {
		t.Fatal(err)
	}
}
