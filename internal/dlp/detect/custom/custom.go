// Package custom runs the admin-defined rules from a policy bundle:
// custom.regex (an RE2 pattern) and custom.keywords (a keyword list). The
// console can't check RE2 exactly, so this package is the authority: a rule
// that doesn't compile is reported and skipped, and the other rules still run.
package custom

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Detector ids.
const (
	RegexID    = "custom.regex"
	KeywordsID = "custom.keywords"
)

// Limits on admin input, so one rule can't make every scan slow.
const (
	MaxPatternBytes   = 4096
	MaxKeywords       = 500
	MaxKeywordBytes   = 256
	maxMatchesPerRule = 1000
	// maxRawMatches bounds the matches examined (and FindAll's memory),
	// empty ones included.
	maxRawMatches = 1 << 16
)

// Spec is one custom rule as the bundle carries it.
type Spec struct {
	DetectorID    string // RegexID or KeywordsID
	RuleID        string
	Pattern       string
	Keywords      []string
	CaseSensitive bool
}

// Rule is a compiled custom rule.
type Rule struct {
	DetectorID string
	RuleID     string
	re         *regexp.Regexp
}

// Match is one finding; Start and End are byte offsets.
type Match struct {
	DetectorID string
	RuleID     string
	Start, End int
}

// Compile compiles one rule.
func Compile(s Spec) (*Rule, error) {
	var pattern string
	switch s.DetectorID {
	case RegexID:
		if s.Pattern == "" {
			return nil, errors.New("empty pattern")
		}
		if len(s.Pattern) > MaxPatternBytes {
			return nil, fmt.Errorf("pattern longer than %d bytes", MaxPatternBytes)
		}
		pattern = s.Pattern
	case KeywordsID:
		p, err := keywordPattern(s.Keywords, s.CaseSensitive)
		if err != nil {
			return nil, err
		}
		pattern = p
	default:
		return nil, fmt.Errorf("not a custom detector: %q", s.DetectorID)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Rule{DetectorID: s.DetectorID, RuleID: s.RuleID, re: re}, nil
}

// keywordPattern builds one RE2 alternation of the quoted keywords. RE2 keeps
// it linear, and its offsets stay exact under case folding (unlike matching a
// lowercased copy of the text).
func keywordPattern(keywords []string, caseSensitive bool) (string, error) {
	if len(keywords) > MaxKeywords {
		return "", fmt.Errorf("more than %d keywords", MaxKeywords)
	}
	quoted := make([]string, 0, len(keywords))
	for _, k := range keywords {
		if k == "" {
			continue
		}
		if len(k) > MaxKeywordBytes {
			return "", fmt.Errorf("keyword longer than %d bytes", MaxKeywordBytes)
		}
		quoted = append(quoted, regexp.QuoteMeta(k))
	}
	if len(quoted) == 0 {
		return "", errors.New("no keywords")
	}
	p := "(?:" + strings.Join(quoted, "|") + ")"
	if !caseSensitive {
		p = "(?i)" + p
	}
	return p, nil
}

// Find returns the rule's matches in text, at most maxMatchesPerRule. Empty
// matches (a pattern like "x*") flag nothing and don't count toward the cap.
func (r *Rule) Find(text string) []Match {
	var out []Match
	for _, loc := range r.re.FindAllStringIndex(text, maxRawMatches) {
		if loc[1] == loc[0] {
			continue
		}
		out = append(out, Match{DetectorID: r.DetectorID, RuleID: r.RuleID, Start: loc[0], End: loc[1]})
		if len(out) == maxMatchesPerRule {
			break
		}
	}
	return out
}
