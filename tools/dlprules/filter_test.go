package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestTranslateFilter_KnownShapes(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want Filter
	}{
		{"empty", "", Filter{}},
		{"entropy below", `entropy(finding["secret"]) < 3.5`, Filter{EntropyBelow: 3.5}},
		{"entropy at most", `entropy(finding["secret"]) <= 3`, Filter{EntropyAtMost: 3}},
		{"filter prefix", `filter.entropy(finding["secret"]) < 3`, Filter{EntropyBelow: 3}},
		{
			"entropy or tokenRatio keeps entropy only",
			"\nfilter.entropy(finding[\"secret\"]) < 3.0 || filter.tokenRatio(finding[\"secret\"]) >= 2.5\n",
			Filter{EntropyBelow: 3},
		},
		{
			"deny-list",
			"entropy(finding[\"secret\"]) <= 3 || matchesAny(finding[\"secret\"], [\n  `.+EXAMPLE$`,\n])",
			Filter{EntropyAtMost: 3, DenyRegex: []string{".+EXAMPLE$"}},
		},
		{
			"required matches",
			`filter.entropy(finding["secret"]) < 3.5 || !filter.matchesAny(finding["secret"], ["[0-9]"]) || !filter.matchesAny(finding["secret"], ["[A-Z]"])`,
			Filter{EntropyBelow: 3.5, RequireRegex: [][]string{{"[0-9]"}, {"[A-Z]"}}},
		},
		{
			"containsAny and path term",
			"(matchesAny(attributes[\"path\"], [`\\.md$`]) || containsAny(finding[\"secret\"], [\"abc\", \"x||y\"]))",
			Filter{DenyContains: []string{"abc", "x||y"}},
		},
		{
			"match deny-list",
			"matchesAny(finding[\"match\"], [`(?i)example`])",
			Filter{DenyMatchRegex: []string{"(?i)example"}},
		},
		{
			"regex containing || inside a raw string",
			"matchesAny(finding[\"secret\"], [`a\\|\\|b`, `(c||d)`])",
			Filter{DenyRegex: []string{`a\|\|b`, `(c||d)`}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := translateFilter(tt.expr)
			if err != nil {
				t.Fatalf("translateFilter: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A filter the generator can't translate must fail, so the rule is dropped
// rather than shipped without (part of) its filter.
func TestTranslateFilter_UnknownShapeFails(t *testing.T) {
	tests := map[string]string{
		"script":            "let x = finding[\"secret\"];\nentropy(x) < 3",
		"comment script":    "// note\nentropy(finding[\"secret\"]) < 3",
		"conjunction":       `entropy(finding["secret"]) < 3 && tokenRatio(finding["secret"]) >= 2`,
		"negated entropy":   `!entropy(finding["secret"]) < 3`,
		"greater entropy":   `entropy(finding["secret"]) > 3`,
		"two entropy terms": `entropy(finding["secret"]) < 3 || entropy(finding["secret"]) <= 2`,
		"unknown function":  `startsWith(finding["secret"], "x")`,
		"unknown target":    "matchesAny(finding[\"line\"], [`x`])",
		"negated path":      "!matchesAny(attributes[\"path\"], [`x`])",
		"bad regex in list": "matchesAny(finding[\"secret\"], [`(`])",
		"bare identifier":   `secret`,
		"unterminated":      "matchesAny(finding[\"secret\"], [`abc])",
	}
	for name, expr := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := translateFilter(expr)
			if !errors.Is(err, errUnknownShape) {
				t.Errorf("translateFilter(%q) = %v, want errUnknownShape", expr, err)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	toml := []byte(`
filter = '''
(matchesAny(finding["secret"], [` + "`^true$`" + `]) || containsAny(finding["secret"], ["abcdefghijklmnopqrstuvwxyz"]))
'''

[[rules]]
id = "zeta-token"
description = "Zeta token."
regex = '''\b(zeta_[a-z0-9]{20})\b'''
confidence = "high"
keywords = ["ZETA_"]
filter = '''entropy(finding["secret"]) < 3'''
validate = '''http.get("https://example.invalid")'''
skipReport = true

[[rules]]
id = "alpha-key"
description = "Alpha key."
regex = '''alpha=(\w+)=(\w+)'''
secretGroup = 2
confidence = "medium"
keywords = ["alpha"]

[[rules]]
id = "low-rule"
regex = '''x'''
confidence = "low"

[[rules]]
id = "path-rule"
regex = '''x'''
path = '''\.tf$'''
confidence = "high"

[[rules]]
id = "script-rule"
regex = '''x'''
confidence = "high"
filter = '''let a = 1; a > 0'''

[[rules]]
id = "bad-group"
regex = '''(x)'''
secretGroup = 2
confidence = "high"
`)
	rs, cat, err := generate(toml, Source{Tag: "v0", Commit: "c0"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rs.Source.SHA256 == "" || rs.Source.Tag != "v0" {
		t.Errorf("source = %+v", rs.Source)
	}
	if len(rs.GlobalFilter.DenyRegex) != 1 || len(rs.GlobalFilter.DenyContains) != 1 {
		t.Errorf("global filter = %+v", rs.GlobalFilter)
	}

	var ids []string
	for _, r := range rs.Rules {
		ids = append(ids, r.ID)
	}
	if want := []string{"alpha-key", "zeta-token"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("shipped %v, want %v (sorted)", ids, want)
	}
	if rs.Rules[0].SecretGroup != 2 || rs.Rules[0].Filter != nil {
		t.Errorf("alpha-key = %+v", rs.Rules[0])
	}
	if z := rs.Rules[1]; z.Keywords[0] != "zeta_" || z.Filter == nil || z.Filter.EntropyBelow != 3 {
		t.Errorf("zeta-token = %+v (keywords lowercased, filter kept)", z)
	}

	dropped := map[string]bool{}
	for _, d := range rs.Dropped {
		dropped[d.ID] = true
	}
	for _, id := range []string{"low-rule", "path-rule", "script-rule", "bad-group"} {
		if !dropped[id] {
			t.Errorf("%s not dropped; dropped = %+v", id, rs.Dropped)
		}
	}
	if len(cat) != 2 || cat[0].ID != "secrets.alpha-key" || cat[1].Description != "Zeta token." {
		t.Errorf("catalog = %+v", cat)
	}
}

// An untranslatable global filter fails the whole run.
func TestGenerate_GlobalFilterMustTranslate(t *testing.T) {
	toml := []byte("filter = '''let a = 1'''\n[[rules]]\nid = \"a\"\nregex = 'a'\nconfidence = \"high\"\n")
	if _, _, err := generate(toml, Source{}); !errors.Is(err, errUnknownShape) {
		t.Errorf("generate = %v, want errUnknownShape", err)
	}
}
