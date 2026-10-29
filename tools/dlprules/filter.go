package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// Filter is a betterleaks filter expression translated into plain fields the
// agent's matcher applies without an expression engine. A finding is
// discarded when any of the conditions holds.
type Filter struct {
	EntropyBelow   float64    `json:"entropy_below,omitempty"`    // entropy(secret) < N
	EntropyAtMost  float64    `json:"entropy_at_most,omitempty"`  // entropy(secret) <= N
	DenyRegex      []string   `json:"deny_regex,omitempty"`       // secret matches any
	DenyContains   []string   `json:"-"`                          // secret contains any (written hex-encoded)
	DenyMatchRegex []string   `json:"deny_match_regex,omitempty"` // the full match matches any
	RequireRegex   [][]string `json:"require_regex,omitempty"`    // secret matches none of a group

	// DenyContainsHex is DenyContains hex-encoded. Upstream deny-lists hold
	// real, publicly known keys (e.g. Google API keys shipped in public apps)
	// that must not be reported; encoding them keeps key-shaped strings out of
	// the repository, where secret scanners would flag them.
	DenyContainsHex []string `json:"deny_contains_hex,omitempty"`
}

// encodeLiterals moves deny-list regexes that are plain literals into
// DenyContains (same meaning: the secret contains the text) and hex-encodes
// DenyContains into DenyContainsHex.
func (f *Filter) encodeLiterals() {
	var regexes []string
	for _, p := range f.DenyRegex {
		if lit, ok := literal(p); ok {
			f.DenyContains = append(f.DenyContains, lit)
			continue
		}
		regexes = append(regexes, p)
	}
	f.DenyRegex = regexes
	for _, s := range f.DenyContains {
		f.DenyContainsHex = append(f.DenyContainsHex, hex.EncodeToString([]byte(s)))
	}
	f.DenyContains = nil
}

// literal reports whether pattern matches exactly one case-sensitive string,
// and returns it.
func literal(pattern string) (string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false
	}
	re = re.Simplify()
	if re.Op != syntax.OpLiteral || re.Flags&syntax.FoldCase != 0 {
		return "", false
	}
	return string(re.Rune), true
}

// errUnknownShape marks a filter the generator can't translate. The rule is
// dropped and listed rather than shipped with a weaker filter.
var errUnknownShape = errors.New("unknown filter shape")

var (
	reCompare = regexp.MustCompile(`^(!?)(?:filter\.)?(entropy|tokenRatio)\(finding\["secret"\]\)\s*(<=|<|>=|>)\s*([0-9]+(?:\.[0-9]+)?)$`)
	reListFn  = regexp.MustCompile(`(?s)^(!?)(?:filter\.)?(matchesAny|containsAny)\((finding\["secret"\]|finding\["match"\]|attributes\["path"\])\s*,\s*\[(.*)\]\s*\)$`)
)

// translateFilter turns a betterleaks filter expression into a Filter. Only
// disjunctions (||) of these terms are understood:
//
//	entropy(finding["secret"]) < N            (or <=)
//	tokenRatio(finding["secret"]) >= N        (ignored: needs a BPE tokenizer; phase 1 is entropy-only)
//	[!]matchesAny(finding["secret"], [...])   (deny-list, or with ! a required match)
//	matchesAny(finding["match"], [...])
//	containsAny(finding["secret"], [...])
//	matchesAny(attributes["path"], [...])     (ignored: a clipboard has no path, so it never holds)
//
// The optional "filter." prefix is accepted. Anything else returns
// errUnknownShape.
func translateFilter(expr string) (Filter, error) {
	var f Filter
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return f, nil
	}
	terms, err := splitOr(stripParens(expr))
	if err != nil {
		return f, err
	}
	for _, term := range terms {
		if err := f.addTerm(stripParens(strings.TrimSpace(term))); err != nil {
			return Filter{}, fmt.Errorf("%w: %q: %v", errUnknownShape, abbreviate(term), err)
		}
	}
	return f, nil
}

func (f *Filter) addTerm(term string) error {
	if m := reCompare.FindStringSubmatch(term); m != nil {
		return f.addCompare(m[1] == "!", m[2], m[3], m[4])
	}
	if m := reListFn.FindStringSubmatch(term); m != nil {
		items, err := parseList(m[4])
		if err != nil {
			return err
		}
		return f.addList(m[1] == "!", m[2], m[3], items)
	}
	return errors.New("not a known term")
}

func (f *Filter) addCompare(negated bool, fn, op, num string) error {
	if negated {
		return errors.New("negated comparison")
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return err
	}
	switch {
	case fn == "tokenRatio" && op == ">=":
		return nil
	case fn == "entropy" && op == "<" && f.EntropyBelow == 0 && f.EntropyAtMost == 0:
		f.EntropyBelow = n
	case fn == "entropy" && op == "<=" && f.EntropyBelow == 0 && f.EntropyAtMost == 0:
		f.EntropyAtMost = n
	default:
		return fmt.Errorf("unsupported %s %s", fn, op)
	}
	return nil
}

func (f *Filter) addList(negated bool, fn, target string, items []string) error {
	if fn == "matchesAny" {
		for _, it := range items {
			if _, err := regexp.Compile(it); err != nil {
				return fmt.Errorf("regex %q: %v", it, err)
			}
		}
	}
	switch {
	case target == `attributes["path"]` && fn == "matchesAny" && !negated:
		return nil
	case target == `finding["secret"]` && fn == "matchesAny" && !negated:
		f.DenyRegex = append(f.DenyRegex, items...)
	case target == `finding["secret"]` && fn == "matchesAny" && negated:
		f.RequireRegex = append(f.RequireRegex, items)
	case target == `finding["secret"]` && fn == "containsAny" && !negated:
		f.DenyContains = append(f.DenyContains, items...)
	case target == `finding["match"]` && fn == "matchesAny" && !negated:
		f.DenyMatchRegex = append(f.DenyMatchRegex, items...)
	default:
		return fmt.Errorf("unsupported %s%s(%s)", map[bool]string{true: "!"}[negated], fn, target)
	}
	return nil
}

// stripParens removes parentheses that enclose the whole of s.
func stripParens(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && closingParen(s) == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// closingParen returns the index of the paren closing s[0], or -1.
func closingParen(s string) int {
	depth := 0
	idx := -1
	_ = scan(s, func(i int, c byte) bool {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				idx = i
				return false
			}
		}
		return true
	})
	return idx
}

// splitOr splits s on "||" outside strings and brackets. A top-level "&&",
// ";" or "let" makes it an unknown shape.
func splitOr(s string) ([]string, error) {
	if strings.HasPrefix(s, "let ") || strings.HasPrefix(s, "//") {
		return nil, fmt.Errorf("%w: script", errUnknownShape)
	}
	var terms []string
	depth, start := 0, 0
	var bad error
	err := scan(s, func(i int, c byte) bool {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '|', '&':
			if depth == 0 && i+1 < len(s) && s[i+1] == c {
				if c == '&' {
					bad = fmt.Errorf("%w: top-level &&", errUnknownShape)
					return false
				}
				terms = append(terms, s[start:i])
				start = i + 2
			}
		case ';':
			if depth == 0 {
				bad = fmt.Errorf("%w: statement list", errUnknownShape)
				return false
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if bad != nil {
		return nil, bad
	}
	return append(terms, s[start:]), nil
}

// scan calls fn for each byte of s outside backtick and double-quoted
// strings, until fn returns false. The second byte of a "||" pair is skipped
// so it isn't seen twice.
func scan(s string, fn func(i int, c byte) bool) error {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return fmt.Errorf("%w: unterminated raw string", errUnknownShape)
			}
			i += end + 1
		case '"':
			j, err := skipQuoted(s, i)
			if err != nil {
				return err
			}
			i = j
		default:
			if !fn(i, c) {
				return nil
			}
			if (c == '|' || c == '&') && i+1 < len(s) && s[i+1] == c {
				i++
			}
		}
	}
	return nil
}

// skipQuoted returns the index of the quote closing the string at s[i].
func skipQuoted(s string, i int) (int, error) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j, nil
		}
	}
	return 0, fmt.Errorf("%w: unterminated string", errUnknownShape)
}

// parseList parses the inside of a list literal: backtick raw strings or
// double-quoted strings, separated by commas, with an optional trailing comma.
func parseList(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ',':
		case '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return nil, errors.New("unterminated raw string")
			}
			out = append(out, s[i+1:i+1+end])
			i += end + 1
		case '"':
			j, err := skipQuoted(s, i)
			if err != nil {
				return nil, err
			}
			v, err := strconv.Unquote(s[i : j+1])
			if err != nil {
				return nil, fmt.Errorf("string %s: %v", s[i:j+1], err)
			}
			out = append(out, v)
			i = j
		default:
			return nil, fmt.Errorf("unexpected %q in list", s[i])
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty list")
	}
	return out, nil
}

func abbreviate(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
