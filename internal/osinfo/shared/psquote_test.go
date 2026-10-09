package shared

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPSQuote(t *testing.T) {
	cases := map[string]string{
		"Ethernet":    `'Ethernet'`,
		"":            `''`,
		"it's":        `'it''s'`,
		"x$(calc)":    `'x$(calc)'`,
		`a"b`:         `'a"b'`,
		"'; calc; '":  `'''; calc; '''`,
		"smart’quote": "'smart’’quote'",
		"‘‚‛":         "'‘‘‚‚‛‛'",
	}
	for in, want := range cases {
		if got := PSQuote(in); got != want {
			t.Errorf("PSQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzPSQuote checks the property that matters: the result is one complete
// single-quoted literal, i.e. no quote character inside it is left unpaired.
func FuzzPSQuote(f *testing.F) {
	for _, s := range []string{"Ethernet", "it's", "x$(calc)", "’", "'''"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		q := PSQuote(s)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") || len(q) < 2 {
			t.Fatalf("PSQuote(%q) = %q: not wrapped in quotes", s, q)
		}
		inner := []rune(q[1 : len(q)-1])
		for i := 0; i < len(inner); i++ {
			if isPSSingleQuote(inner[i]) {
				if i+1 >= len(inner) || inner[i+1] != inner[i] {
					t.Fatalf("PSQuote(%q) = %q: unpaired quote at rune %d", s, q, i)
				}
				i++
			}
		}
	})
}

func isPSSingleQuote(r rune) bool {
	switch r {
	case '\'', '‘', '’', '‚', '‛':
		return true
	}
	return false
}
