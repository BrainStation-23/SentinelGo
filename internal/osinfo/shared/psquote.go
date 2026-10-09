package shared

import "strings"

// PSQuote returns s as a PowerShell single-quoted string literal, safe to
// splice into a script passed to RunPowerShell.
//
// Values that come from the device (adapter names, account names) must never
// be pasted into a script raw: inside double quotes PowerShell runs $(...)
// subexpressions, and an unescaped quote ends the literal. Either way the
// value would become code running with the agent's privileges (CWE-78).
//
// Single-quoted literals expand nothing; the only special character is the
// quote itself, escaped by doubling it. PowerShell also accepts the Unicode
// quotes U+2018, U+2019, U+201A and U+201B as single quotes, so those are
// doubled too.
func PSQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '‘', '’', '‚', '‛':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}
