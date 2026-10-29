package custom

import (
	"regexp"
	"strings"
	"testing"
)

func TestCompile_Errors(t *testing.T) {
	tests := map[string]Spec{
		"bad regex":       {DetectorID: RegexID, RuleID: "r", Pattern: "missing closing ("},
		"lookahead":       {DetectorID: RegexID, RuleID: "r", Pattern: "a(?=b)"},
		"empty pattern":   {DetectorID: RegexID, RuleID: "r"},
		"pattern too big": {DetectorID: RegexID, RuleID: "r", Pattern: strings.Repeat("a", MaxPatternBytes+1)},
		"no keywords":     {DetectorID: KeywordsID, RuleID: "r", Keywords: []string{"", ""}},
		"too many":        {DetectorID: KeywordsID, RuleID: "r", Keywords: make([]string, MaxKeywords+1)},
		"keyword too big": {DetectorID: KeywordsID, RuleID: "r", Keywords: []string{strings.Repeat("k", MaxKeywordBytes+1)}},
		"not custom":      {DetectorID: "pii.iban", RuleID: "r"},
	}
	for name, s := range tests {
		if _, err := Compile(s); err == nil {
			t.Errorf("%s: Compile succeeded", name)
		}
	}
}

func TestKeywords_AreLiteral(t *testing.T) {
	r, err := Compile(Spec{DetectorID: KeywordsID, RuleID: "k", Keywords: []string{"a.b", "(x)"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Find("axb a.b (x) x"); len(got) != 2 {
		t.Errorf("Find = %+v, want the two literal matches", got)
	}
}

func TestKeywords_CaseFoldingKeepsOffsets(t *testing.T) {
	r, err := Compile(Spec{DetectorID: KeywordsID, RuleID: "k", Keywords: []string{"secret"}})
	if err != nil {
		t.Fatal(err)
	}
	text := "İİİ SECRET"
	got := r.Find(text)
	if len(got) != 1 || text[got[0].Start:got[0].End] != "SECRET" {
		t.Errorf("Find = %+v", got)
	}
}

// Empty matches don't use up the cap and hide a later real match.
func TestRegex_EmptyMatchesDontUseTheCap(t *testing.T) {
	r, err := Compile(Spec{DetectorID: RegexID, RuleID: "r", Pattern: "x*"})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Find(strings.Repeat("a", 5000) + "x"); len(got) != 1 {
		t.Errorf("Find = %d matches, want the x after 5000 empty matches", len(got))
	}
}

func TestRegex_EmptyMatchesIgnored(t *testing.T) {
	r, err := Compile(Spec{DetectorID: RegexID, RuleID: "r", Pattern: "x*"})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Find("abc"); len(got) != 0 {
		t.Errorf("empty matches reported: %+v", got)
	}
}

func FuzzCompile(f *testing.F) {
	f.Add(`(?i)project-falcon-\d+`, "CONFIDENTIAL", "project-falcon-9 is confidential")
	f.Add("(", "", "")
	f.Add(`a{1000}`, "x|y", "xyz")
	f.Fuzz(func(t *testing.T, pattern, keyword, text string) {
		r, err := Compile(Spec{DetectorID: RegexID, RuleID: "r", Pattern: pattern})
		_, stdErr := regexp.Compile(pattern)
		if err == nil && stdErr != nil {
			t.Fatalf("Compile accepted %q that RE2 rejects", pattern)
		}
		if r != nil {
			checkMatches(t, r.Find(text), text)
		}
		k, err := Compile(Spec{DetectorID: KeywordsID, RuleID: "k", Keywords: []string{keyword}})
		if err == nil {
			checkMatches(t, k.Find(text), text)
		}
	})
}

func checkMatches(t *testing.T, ms []Match, text string) {
	t.Helper()
	for _, m := range ms {
		if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
			t.Fatalf("match %+v out of range for %d bytes", m, len(text))
		}
	}
}
