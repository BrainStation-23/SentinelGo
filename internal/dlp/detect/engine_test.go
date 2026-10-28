package detect

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// defaultRules is secrets.all plus the default (not opt-in) PII detectors.
func defaultRules() []Rule {
	return []Rule{
		{DetectorID: SecretsAll, RuleID: "r-secrets"},
		{DetectorID: "pii.credit_card", RuleID: "r-cc"},
		{DetectorID: "pii.iban", RuleID: "r-iban"},
		{DetectorID: "pii.us_ssn", RuleID: "r-ssn"},
		{DetectorID: "pii.uk_nino", RuleID: "r-nino"},
		{DetectorID: "pii.uk_nhs", RuleID: "r-nhs"},
	}
}

func newEngine(t testing.TB, rules []Rule) *Engine {
	t.Helper()
	e, errs := New(rules, 0)
	if len(errs) > 0 {
		t.Fatalf("compile errors: %+v", errs)
	}
	return e
}

func detectorIDs(fs []Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.DetectorID)
	}
	return ids
}

func TestScan_SecretTruePositives(t *testing.T) {
	e := newEngine(t, defaultRules())
	for _, s := range secretSamples() {
		t.Run(s.name, func(t *testing.T) {
			res := e.Scan(s.text)
			if !slices.Contains(detectorIDs(res.Findings), s.want) {
				t.Errorf("findings %v, want %s", detectorIDs(res.Findings), s.want)
			}
		})
	}
}

// Each specific secret detector fires on its own, without secrets.all.
func TestScan_SpecificSecretDetector(t *testing.T) {
	for _, s := range secretSamples() {
		t.Run(s.name, func(t *testing.T) {
			e := newEngine(t, []Rule{{DetectorID: s.want, RuleID: "r1"}})
			res := e.Scan(s.text)
			if !slices.Contains(detectorIDs(res.Findings), s.want) {
				t.Errorf("findings %v, want %s", detectorIDs(res.Findings), s.want)
			}
			for _, f := range res.Findings {
				if f.DetectorID != s.want {
					t.Errorf("detector %s fired, but only %s is enabled", f.DetectorID, s.want)
				}
			}
		})
	}
}

func TestScan_ClipboardFalsePositives(t *testing.T) {
	e := newEngine(t, defaultRules())
	for _, text := range clipboardFalsePositives {
		if res := e.Scan(text); len(res.Findings) > 0 {
			t.Errorf("%q: unexpected findings %v", text, detectorIDs(res.Findings))
		}
	}
}

func TestScan_PII(t *testing.T) {
	e := newEngine(t, defaultRules())
	tests := []struct{ text, want string }{
		{"card 4111 1111 1111 1111 exp 12/29", "pii.credit_card"},
		{"iban GB82 WEST 1234 5698 7654 32", "pii.iban"},
		{"ssn 536-22-1234", "pii.us_ssn"},
		{"nino AB123456C", "pii.uk_nino"},
		{"nhs 943 476 5919", "pii.uk_nhs"},
	}
	for _, tt := range tests {
		if got := detectorIDs(e.Scan(tt.text).Findings); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("%q: findings %v, want [%s]", tt.text, got, tt.want)
		}
	}
}

func TestScan_FindingNeverCarriesRawMatch(t *testing.T) {
	e := newEngine(t, defaultRules())
	text := "card 4111111111111111 and 5555555555554444"
	res := e.Scan(text)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Count != 2 || len(f.Offsets) != 2 {
		t.Errorf("count=%d offsets=%v, want 2", f.Count, f.Offsets)
	}
	if strings.Contains(fmt.Sprintf("%+v", f), "4111111111111111") {
		t.Errorf("finding carries the raw match: %+v", f)
	}
	if f.Masked != "4111********1111" {
		t.Errorf("Masked = %q", f.Masked)
	}
	if len(f.SHA256) != 64 {
		t.Errorf("SHA256 = %q", f.SHA256)
	}
	if got := text[f.Offsets[1][0]:f.Offsets[1][1]]; got != "5555555555554444" {
		t.Errorf("second offset points at %q", got)
	}
}

func TestScan_CustomRules(t *testing.T) {
	e := newEngine(t, []Rule{
		{DetectorID: "custom.regex", RuleID: "falcon", Pattern: `(?i)project-falcon-\d+`},
		{DetectorID: "custom.keywords", RuleID: "conf", Keywords: []string{"CONFIDENTIAL", "Internal Only"}},
		{DetectorID: "custom.keywords", RuleID: "exact", Keywords: []string{"Secret Sauce"}, CaseSensitive: true},
	})
	res := e.Scan("PROJECT-FALCON-42 is confidential; internal only. secret sauce vs Secret Sauce")
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID] = f.Count
	}
	want := map[string]int{"falcon": 1, "conf": 2, "exact": 1}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("rule %s count = %d, want %d (all: %v)", id, got[id], n, got)
		}
	}
}

func TestNew_BadRulesReportedOthersActive(t *testing.T) {
	rules := []Rule{
		{DetectorID: "custom.regex", RuleID: "bad", Pattern: "missing closing ("},
		{DetectorID: "custom.regex", RuleID: "lookahead", Pattern: `foo(?=bar)`},
		{DetectorID: "custom.keywords", RuleID: "empty"},
		{DetectorID: "pii.martian_id", RuleID: "unknown-pii"},
		{DetectorID: "secrets.no-such-rule", RuleID: "unknown-secret"},
		{DetectorID: "ml.classifier", RuleID: "unknown-family"},
		{DetectorID: "custom.regex", RuleID: "good", Pattern: `falcon-\d+`},
	}
	e, errs := New(rules, 0)
	failed := map[string]bool{}
	for _, ce := range errs {
		failed[ce.RuleID] = true
		if ce.Error == "" {
			t.Errorf("compile error for %s has no message", ce.RuleID)
		}
	}
	for _, id := range []string{"bad", "lookahead", "empty", "unknown-pii", "unknown-secret", "unknown-family"} {
		if !failed[id] {
			t.Errorf("rule %s not reported as a compile error (errs: %+v)", id, errs)
		}
	}
	if failed["good"] {
		t.Error("good rule reported as failed")
	}
	res := e.Scan("falcon-7")
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "good" {
		t.Errorf("findings = %+v, want the good rule", res.Findings)
	}
	// match:all must ignore the skipped rules, or one bad rule disables the policy.
	if ok, _ := e.Evaluate(MatchAll, rules, res); !ok {
		t.Error("Evaluate(all) = false; skipped rules must not count")
	}
}

func TestEvaluate(t *testing.T) {
	findings := Result{Findings: []Finding{
		{DetectorID: "pii.credit_card", Count: 2},
		{DetectorID: "secrets.github-pat", Count: 1},
		{DetectorID: "secrets.aws-access-token", Count: 1},
		{DetectorID: "custom.regex", RuleID: "r-falcon", Count: 1},
	}}
	e := &Engine{inactive: map[string]bool{}}
	tests := []struct {
		name      string
		match     string
		rules     []Rule
		want      bool
		wantCount int // findings returned
	}{
		{"any: one detector", MatchAny, []Rule{{DetectorID: "pii.credit_card"}}, true, 1},
		{"any: min_count met", MatchAny, []Rule{{DetectorID: "pii.credit_card", MinCount: 2}}, true, 1},
		{"any: min_count not met", MatchAny, []Rule{{DetectorID: "pii.credit_card", MinCount: 3}}, false, 0},
		{"secrets.all sums every secret rule", MatchAny, []Rule{{DetectorID: SecretsAll, MinCount: 2}}, true, 2},
		{"custom rule matched by rule id", MatchAny, []Rule{{DetectorID: "custom.regex", RuleID: "r-falcon"}}, true, 1},
		{"custom rule with another id", MatchAny, []Rule{{DetectorID: "custom.regex", RuleID: "r-other"}}, false, 0},
		{"all: every rule met", MatchAll, []Rule{{DetectorID: "pii.credit_card"}, {DetectorID: "secrets.github-pat"}}, true, 2},
		{"all: one rule unmet", MatchAll, []Rule{{DetectorID: "pii.credit_card"}, {DetectorID: "pii.iban"}}, false, 0},
		{"any: only matched findings returned", MatchAny, []Rule{{DetectorID: "pii.iban"}, {DetectorID: "secrets.github-pat"}}, true, 1},
		{"no rules", MatchAny, nil, false, 0},
		{"no rules all", MatchAll, nil, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, used := e.Evaluate(tt.match, tt.rules, findings)
			if ok != tt.want || len(used) != tt.wantCount {
				t.Errorf("Evaluate = %v with %d findings, want %v with %d", ok, len(used), tt.want, tt.wantCount)
			}
		})
	}
}

func TestScan_TruncatesAtLimit(t *testing.T) {
	e, _ := New([]Rule{{DetectorID: "custom.keywords", RuleID: "k", Keywords: []string{"needle"}}}, 64)
	head := "a" + strings.Repeat("é", 31) // 63 bytes; the next "é" spans bytes 63–64
	res := e.Scan(head + "é" + "needle")
	if !res.Truncated {
		t.Error("Truncated = false")
	}
	if res.ScannedBytes != 63 {
		t.Errorf("ScannedBytes = %d, want 63 (cut on a rune boundary)", res.ScannedBytes)
	}
	if len(res.Findings) != 0 {
		t.Errorf("text past the limit was scanned: %+v", res.Findings)
	}
	if res := e.Scan("needle"); res.Truncated || len(res.Findings) != 1 {
		t.Errorf("short text: %+v", res)
	}
}

func TestMask(t *testing.T) {
	tests := map[string]string{
		"":                     "",
		"a":                    "*",
		"abc":                  "***",
		"abcd":                 "a**d",
		"abcdefgh":             "ab****gh",
		"4111111111111111":     "4111********1111",
		strings.Repeat("x", 9): "xx*****xx",
		"abcd" + strings.Repeat("-", 100) + "wxyz": "abcd************wxyz",
		"ключ-секрет":                              "кл*******ет",
	}
	for in, want := range tests {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSupportedDetectors(t *testing.T) {
	ids := SupportedDetectors()
	for _, want := range []string{
		SecretsAll, "secrets.aws-access-token", "secrets.github-pat",
		"pii.credit_card", "pii.iban", "pii.us_ssn", "pii.uk_nino", "pii.uk_nhs", "pii.email", "pii.phone",
		"custom.regex", "custom.keywords",
	} {
		if !slices.Contains(ids, want) {
			t.Errorf("SupportedDetectors() lacks %s", want)
		}
	}
	for _, never := range []string{"pii.us_bank_number", "pii.date_time", "pii.url", "pii.ip_address", "pii.person"} {
		if slices.Contains(ids, never) {
			t.Errorf("SupportedDetectors() offers excluded %s", never)
		}
	}
	if !slices.IsSorted(ids) {
		t.Error("SupportedDetectors() not sorted")
	}
}

func FuzzScan(f *testing.F) {
	for _, s := range secretSamples() {
		f.Add(s.text)
	}
	for _, s := range clipboardFalsePositives {
		f.Add(s)
	}
	f.Add("card 4111 1111 1111 1111 project-falcon-9 CONFIDENTIAL")
	f.Add(string([]byte{0xff, 0xfe, 'A', 'K', 'I', 'A', 0}))

	rules := append(defaultRules(),
		Rule{DetectorID: "pii.email", RuleID: "r-email"},
		Rule{DetectorID: "pii.phone", RuleID: "r-phone"},
		Rule{DetectorID: "custom.regex", RuleID: "r-re", Pattern: `(?i)project-falcon-\d+`},
		Rule{DetectorID: "custom.keywords", RuleID: "r-kw", Keywords: []string{"confidential"}},
	)
	e, errs := New(rules, 4096)
	if len(errs) > 0 {
		f.Fatalf("compile errors: %+v", errs)
	}
	f.Fuzz(func(t *testing.T, text string) {
		res := e.Scan(text)
		if res.ScannedBytes > len(text) || res.ScannedBytes > 4096 {
			t.Fatalf("ScannedBytes = %d for %d bytes", res.ScannedBytes, len(text))
		}
		for _, fd := range res.Findings {
			checkFinding(t, fd, text[:res.ScannedBytes])
		}
		e.Evaluate(MatchAll, rules, res)
	})
}

// checkFinding asserts a finding's invariants: consistent count, offsets
// inside the scanned text, and a masked form that hides the match.
func checkFinding(t *testing.T, fd Finding, scanned string) {
	t.Helper()
	if fd.Count != len(fd.Offsets) || fd.Count == 0 {
		t.Fatalf("count %d, offsets %d", fd.Count, len(fd.Offsets))
	}
	for _, o := range fd.Offsets {
		if o[0] < 0 || o[1] > len(scanned) || o[0] >= o[1] {
			t.Fatalf("offset %v out of range for %d bytes", o, len(scanned))
		}
	}
	first := scanned[fd.Offsets[0][0]:fd.Offsets[0][1]]
	if utf8.RuneCountInString(fd.Masked) > utf8.RuneCountInString(first) || !strings.Contains(fd.Masked, "*") {
		t.Fatalf("Masked %q doesn't hide %d-rune match", fd.Masked, utf8.RuneCountInString(first))
	}
}

// BenchmarkScan64KB scans 64 KB of mixed code and prose with every default
// detector, a few secrets and card numbers in it. Target: p99 < 20 ms.
func BenchmarkScan64KB(b *testing.B) {
	e := newEngine(b, defaultRules())
	text := benchText(64 << 10)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		e.Scan(text)
	}
}

func benchText(size int) string {
	parts := []string{
		"func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {\n",
		"\tkey := os.Getenv(\"API_KEY\") // token secret access\n",
		"The quarterly report is attached; revenue grew 12.5% to $4,300,000.\n",
		"SELECT id, name FROM users WHERE created_at > now() - interval '7 days';\n",
		"https://example.com/search?q=go&page=2&id=1234567890\n",
	}
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		b.WriteString(parts[i%len(parts)])
		if i%200 == 0 {
			b.WriteString("card 4111 1111 1111 1111\n")
			b.WriteString(secretSamples()[i/200%len(secretSamples())].text + "\n")
		}
	}
	return b.String()[:size]
}
