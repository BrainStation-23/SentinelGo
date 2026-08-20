package identity

import "strings"

// placeholders are values firmware vendors ship instead of leaving a field
// empty. Every platform file filters through isPlaceholder so a placeholder
// string never masquerades as a real asset tag, UUID or serial number.
var placeholders = []string{
	"to be filled by o.e.m.",
	"default string",
	"system serial number",
	"not specified",
	"none",
	"0123456789",
	"00000000-0000-0000-0000-000000000000",
}

// isPlaceholder reports whether s is a known firmware placeholder rather than
// real data, case-insensitively and trimmed.
func isPlaceholder(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return true
	}
	for _, p := range placeholders {
		if s == p {
			return true
		}
	}
	return false
}

// clean returns s trimmed, or "" if it is a placeholder.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if isPlaceholder(s) {
		return ""
	}
	return s
}
