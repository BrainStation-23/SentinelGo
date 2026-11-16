package report

import (
	"encoding/json"
	"strings"
	"time"

	"sentinelgo/internal/yara"
)

// Coverage is the contract v1.2 report of a scan (#497): why files were
// skipped or failed, what was read, how long the scan waited, and a sample
// of the files it couldn't scan. It is saved with a checkpoint (Progress),
// so a resumed scheduled scan keeps its counts.
type Coverage struct {
	Skipped   map[string]int64   `json:"skipped,omitempty"`
	Errors    map[string]int64   `json:"errors,omitempty"`
	Bytes     int64              `json:"bytes,omitempty"`
	Throttled time.Duration      `json:"throttled,omitempty"`
	Problems  []yara.ProblemFile `json:"problems,omitempty"`
	// ProblemErrors is how many of Problems are errors; they come first.
	ProblemErrors int `json:"problem_errors,omitempty"`
}

// expectedSkips need no action: counts only, never a problem file.
var expectedSkips = map[string]bool{"excluded": true, "link": true, "unchanged": true}

// Skip counts n files skipped for reason.
func (s *Scan) Skip(reason string, n int64) { add(&s.cov.Skipped, reason, n) }

// Fail counts n errors for reason.
func (s *Scan) Fail(reason string, n int64) { add(&s.cov.Errors, reason, n) }

// AddBytes counts bytes the workers read.
func (s *Scan) AddBytes(n int64) { s.cov.Bytes += max(n, 0) }

// AddThrottled counts time the scan waited on its CPU budget or battery.
func (s *Scan) AddThrottled(d time.Duration) { s.cov.Throttled += max(d, 0) }

// SetEndReason records why the scan stopped early (yara.End*).
func (s *Scan) SetEndReason(r string) { s.endReason = r }

func add(m *map[string]int64, reason string, n int64) {
	if n <= 0 || reason == "" {
		return
	}
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[reason] += n
}

// Problem keeps path in the problem-file sample, with the path evidence of
// a match: errors first, at most yara.MaxProblemFiles. Expected skips are
// left out. detail is the OS error text (no path, no content).
func (s *Scan) Problem(path, reason, detail string, size int64, isErr bool) {
	if !yara.IsReason(reason) || path == "" || (!isErr && expectedSkips[reason]) {
		return
	}
	c := &s.cov
	full := len(c.Problems) >= yara.MaxProblemFiles
	if full && (!isErr || c.ProblemErrors >= yara.MaxProblemFiles) {
		return
	}
	p, h, ext := s.pathEvidence(path)
	pf := yara.ProblemFile{Path: p, PathHash: h, FileExt: ext, Reason: reason,
		Detail: yara.Truncate(strings.ToValidUTF8(detail, ""), yara.MaxProblemDetail), Size: max(size, 0)}
	if !isErr {
		c.Problems = append(c.Problems, pf)
		return
	}
	if full {
		c.Problems = c.Problems[:len(c.Problems)-1] // an error replaces the last skip
	}
	c.Problems = append(c.Problems, yara.ProblemFile{})
	copy(c.Problems[c.ProblemErrors+1:], c.Problems[c.ProblemErrors:])
	c.Problems[c.ProblemErrors] = pf
	c.ProblemErrors++
}

// restoreCoverage merges coverage saved with a checkpoint.
func (s *Scan) restoreCoverage(c Coverage) {
	for k, v := range c.Skipped {
		s.Skip(k, v)
	}
	for k, v := range c.Errors {
		s.Fail(k, v)
	}
	s.AddBytes(c.Bytes)
	s.AddThrottled(c.Throttled)
	n := min(max(c.ProblemErrors, 0), len(c.Problems))
	for i, p := range c.Problems {
		s.restoreProblem(p, i < n)
	}
}

func (s *Scan) restoreProblem(p yara.ProblemFile, isErr bool) {
	c := &s.cov
	if len(c.Problems) >= yara.MaxProblemFiles {
		return
	}
	if isErr {
		c.Problems = append(c.Problems, yara.ProblemFile{})
		copy(c.Problems[c.ProblemErrors+1:], c.Problems[c.ProblemErrors:])
		c.Problems[c.ProblemErrors] = p
		c.ProblemErrors++
		return
	}
	c.Problems = append(c.Problems, p)
}

func (s *Scan) coverage() Coverage {
	c := s.cov
	c.Skipped, c.Errors = cloneCounts(c.Skipped), cloneCounts(c.Errors)
	c.Problems = append([]yara.ProblemFile(nil), c.Problems...)
	return c
}

func cloneCounts(m map[string]int64) map[string]int64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SetScope records what the scan covers. In hashed path mode folders are
// sent as path hashes, like match paths; a folder over the server's length
// limit is hashed in either mode.
func (s *Scan) SetScope(roots, exclusions []string, l yara.Limits, rulesets []yara.Ruleset) {
	sc := &yara.Scope{Roots: s.scopePaths(roots, yara.MaxScopeRoots),
		Exclusions: s.scopePaths(exclusions, yara.MaxScopeExclusions),
		Limits: yara.ScopeLimits{MaxFileBytes: max(l.MaxFileBytes, 0), PerFileTimeoutMS: max(l.PerFileTimeoutMS, 0),
			MaxScanMinutes: max(l.MaxScanMinutes, 0), MaxFilesPerScan: max(l.MaxFilesPerScan, 0)},
		Rulesets: []yara.ScopeRuleset{}}
	for _, r := range rulesets {
		if yara.IsUUID(r.ID) && len(sc.Rulesets) < yara.MaxRulesets {
			sc.Rulesets = append(sc.Rulesets, yara.ScopeRuleset{ID: strings.ToLower(r.ID), Revision: max(r.Revision, 0)})
		}
	}
	// Exclusions go first if the scope is too big, then roots.
	for len(scopeJSON(sc)) > yara.MaxScopeBytes && len(sc.Exclusions) > 0 {
		sc.Exclusions = sc.Exclusions[:len(sc.Exclusions)/2]
	}
	for len(scopeJSON(sc)) > yara.MaxScopeBytes && len(sc.Roots) > 0 {
		sc.Roots = sc.Roots[:len(sc.Roots)/2]
	}
	s.scope = sc
}

func (s *Scan) scopePaths(paths []string, maxN int) []string {
	out := []string{}
	for _, p := range paths {
		if p == "" || len(out) >= maxN {
			continue
		}
		if s.hashPaths || len(p) > yara.MaxPathLen {
			p = HashPath(p)
		}
		out = append(out, p)
	}
	return out
}

func scopeJSON(sc *yara.Scope) []byte {
	data, _ := json.Marshal(sc)
	return data
}

// fill sets the summary's report fields.
func (s *Scan) fill(sum *yara.ScanSummary) {
	sum.SkippedByReason = validCounts(s.cov.Skipped)
	sum.ErrorsByReason = validCounts(s.cov.Errors)
	if yara.ValidEndReason(s.endReason) && sum.State != yara.ScanCompleted {
		sum.EndReason = s.endReason
	}
	sum.BytesScanned = s.cov.Bytes
	sum.ThrottledSeconds = int64(s.cov.Throttled / time.Second)
	sum.Scope = s.scope
	if len(s.cov.Problems) > 0 {
		sum.ProblemFiles = append([]yara.ProblemFile(nil), s.cov.Problems...)
	}
	fitSummary(sum)
}

// validCounts keeps the reasons the server accepts, at most yara.MaxReasons.
func validCounts(m map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range m {
		if yara.IsReason(k) && v > 0 && len(out) < yara.MaxReasons {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fitSummary keeps the summary within yara.MaxSummaryBytes: problem files
// go first, then rule counts (which then can't clear a rule).
func fitSummary(sum *yara.ScanSummary) {
	if summarySize(sum) <= yara.MaxSummaryBytes {
		return
	}
	all := sum.ProblemFiles
	sum.ProblemFiles = all[:longestFit(len(all), func(n int) bool {
		sum.ProblemFiles = all[:n]
		return summarySize(sum) <= yara.MaxSummaryBytes
	})]
	if len(sum.ProblemFiles) == 0 {
		sum.ProblemFiles = nil
	}
	if summarySize(sum) <= yara.MaxSummaryBytes {
		return
	}
	counts := sum.RuleCounts
	sum.RuleCounts = counts[:longestFit(len(counts), func(n int) bool {
		sum.RuleCounts = counts[:n]
		return summarySize(sum) <= yara.MaxSummaryBytes
	})]
	sum.RuleCountsTruncated = true
}

func summarySize(sum *yara.ScanSummary) int {
	data, _ := json.Marshal(sum)
	return len(data)
}

// longestFit returns the largest n in [0, total] with fits(n), for fits
// true up to some n and false after it.
func longestFit(total int, fits func(int) bool) int {
	lo, hi := 0, total // fits(lo) is assumed; hi may not fit
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}
