package software

import (
	"strings"
	"testing"
)

func TestSanitizeHomepageURL(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxHomepageLen)
	cases := map[string]string{
		"https://www.7-zip.org/":      "https://www.7-zip.org/",
		"  http://example.com/help  ": "http://example.com/help",
		"HTTPS://Example.com":         "HTTPS://Example.com",
		"":                            "",
		"javascript:alert(1)":         "",
		"file:///C:/Windows/System32": "",
		"www.example.com":             "",
		"mailto:support@example.com":  "",
		"https://":                    "",
		"https://exa mple.com":        "",
		"https://example.com/\nnext":  "",
		long:                          "",
		long[:maxHomepageLen]:         long[:maxHomepageLen],
	}
	for in, want := range cases {
		if got := sanitizeHomepageURL(in); got != want {
			t.Errorf("sanitizeHomepageURL(%q) = %q, want %q", in, got, want)
		}
	}
}
