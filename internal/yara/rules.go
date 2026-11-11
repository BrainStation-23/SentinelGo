package yara

// RuleSource is one ruleset's verified source (its SHA-256 and size matched
// the bundle), as the ruleset sync hands it to the scan workers to compile.
// Source is rule text from the backend, never file content; it is not
// logged either (rule names and ids only).
type RuleSource struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Source   []byte `json:"source"`
}

// CompileResult is how one ruleset compiled in a worker. Error is set when
// the ruleset as a whole didn't compile (no rule compiled, include, too
// many rules, timeout); Skipped lists the single rules left out.
type CompileResult struct {
	ID       string        `json:"id"`
	Revision int           `json:"revision"`
	Rules    int           `json:"rules"`
	Skipped  []SkippedRule `json:"skipped,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// RulesetStatus converts r for the status report. A ruleset that failed as
// a whole is reported with no compiled rules and its error as a skipped
// "rule" named after the ruleset.
func (r CompileResult) RulesetStatus() RulesetStatus {
	st := RulesetStatus{ID: r.ID, Revision: r.Revision, CompiledRules: r.Rules, SkippedRules: r.Skipped}
	if r.Error != "" {
		st.CompiledRules = 0
		st.SkippedRules = append([]SkippedRule{{Rule: "(ruleset)", Reason: Truncate(r.Error, MaxErrorLen)}}, r.Skipped...)
	}
	if st.SkippedRules == nil {
		st.SkippedRules = []SkippedRule{}
	}
	return st
}
