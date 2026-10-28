package secrets

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// Every shipped rule must compile with Go's RE2, or it would silently never
// match at runtime (rules compile lazily).
func TestEmbeddedRulesetCompiles(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rs.Source().Tag == "" || rs.Source().Commit == "" {
		t.Errorf("source not recorded: %+v", rs.Source())
	}
	if n := len(rs.IDs()); n < 400 {
		t.Errorf("%d rules embedded, want the full ruleset (>400)", n)
	}
	for _, r := range rs.rules {
		if err := r.compile(); err != nil {
			t.Errorf("rule %s: %v", r.spec.ID, err)
		}
		if r.spec.Confidence != "high" && r.spec.Confidence != "medium" {
			t.Errorf("rule %s has confidence %q", r.spec.ID, r.spec.Confidence)
		}
	}
}

func TestFind_FiltersApply(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	only := func(id string) func(string) bool { return func(s string) bool { return s == id } }

	// The aws-access-token rule denies AWS's documentation example key.
	example := "AK" + "IAIOSFODNN7" + "EXAMPLE"
	if got := rs.Find("key "+example, only("aws-access-token")); len(got) != 0 {
		t.Errorf("documentation example flagged: %+v", got)
	}
	// Low entropy is discarded (entropy_at_most 3).
	if got := rs.Find("gh"+"p_"+strings.Repeat("ab", 18), only("github-pat")); len(got) != 0 {
		t.Errorf("low-entropy token flagged: %+v", got)
	}
}

// Rules run only on their keyword's line, but offsets must still point into
// the whole text, and a multi-line rule must still see the whole text.
func TestFind_OffsetsAcrossLines(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	token := "gh" + "p_" + "Zq3XbN7vLk2RtY8wPm4HsJd6FcGa1Ue9Wo5T"
	text := "line one\nline two\nexport GH_TOKEN=" + token + "\nline four\n"
	got := rs.Find(text, func(id string) bool { return id == "github-pat" })
	if len(got) != 1 || text[got[0].Start:got[0].End] != token {
		t.Fatalf("Find = %+v, want the token on line 3", got)
	}

	if !spansLines(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----[\s\S-]{64,}?KEY-----`) {
		t.Error("PEM rule should be treated as multi-line")
	}
	if spansLines(`\b(ghp_[0-9a-zA-Z]{36})(?:[\s;]|$)`) {
		t.Error("single-line token rule treated as multi-line")
	}
}

func TestSecretSpan(t *testing.T) {
	// whole match 0-10, group 1 empty (-1), group 2 at 3-7
	loc := []int{0, 10, -1, -1, 3, 7}
	if s, e := secretSpan(loc, 0); s != 3 || e != 7 {
		t.Errorf("first non-empty group = %d,%d, want 3,7", s, e)
	}
	if s, e := secretSpan(loc, 2); s != 3 || e != 7 {
		t.Errorf("group 2 = %d,%d", s, e)
	}
	if s, _ := secretSpan(loc, 5); s != -1 {
		t.Error("out-of-range group not rejected")
	}
	if s, e := secretSpan([]int{2, 9}, 0); s != 2 || e != 9 {
		t.Errorf("no groups = %d,%d, want the whole match", s, e)
	}
}

func TestEntropy(t *testing.T) {
	tests := map[string]float64{"": 0, "aaaa": 0, "ab": 1, "abcd": 2, "aabb": 1}
	for in, want := range tests {
		if got := Entropy(in); math.Abs(got-want) > 1e-9 {
			t.Errorf("Entropy(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAsciiLowerKeepsOffsets(t *testing.T) {
	in := "İSTANBUL KEY ẞ"
	out := asciiLower(in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), len(out))
	}
	if !strings.Contains(out, "stanbul key") {
		t.Errorf("asciiLower = %q", out)
	}
}

// Upstream deny-lists publicly known keys (shipped hex-encoded); scanning one
// must not report it.
func TestFind_HexDenyListApplies(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	r := rs.rules[rs.byID["gcp-api-key"]]
	if r.spec.Filter == nil || len(r.spec.Filter.DenyContains) == 0 {
		t.Fatal("gcp-api-key has no hex deny-list")
	}
	known, err := hex.DecodeString(r.spec.Filter.DenyContains[1])
	if err != nil {
		t.Fatal(err)
	}
	gcp := func(id string) bool { return id == "gcp-api-key" }
	if got := rs.Find("key: "+string(known)+"\n", gcp); len(got) != 0 {
		t.Errorf("deny-listed key reported: %+v", got)
	}
	other := "AI" + "za" + "Sy" + "Qx7Kp2Lm9Vb4Nc8Rt1Wz6Yd3Fg5Hj0Sk2"
	if got := rs.Find("key: "+other+"\n", gcp); len(got) != 1 {
		t.Errorf("unlisted key not reported: %+v", got)
	}
}
