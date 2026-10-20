package software

// Fuzz targets for the helpers that normalize software metadata taken from
// package managers. Package metadata (maintainer, vendor, architecture) is
// written by the package's author, so it is untrusted input.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzNormalizeArch$' -fuzztime=1m ./internal/service/software/

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzNormalizeArch(f *testing.F) {
	for _, s := range []string{"", "amd64", "x86_64", "AMD64", "arch_arm_i64", "(none)", " noarch ", "ppc64le", "\x00", "ARM64\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := normalizeArch(s)
		if again := normalizeArch(got); again != got {
			t.Errorf("normalizeArch is not idempotent: %q -> %q -> %q", s, got, again)
		}
		if got != strings.TrimSpace(got) {
			t.Errorf("normalizeArch(%q) = %q has surrounding space", s, got)
		}
	})
}

func FuzzStripEmail(f *testing.F) {
	for _, s := range []string{"Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>", "<x@y>", "a<b<c", "", "Name", "Ünïcode <ü@x>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := stripEmail(s)
		if strings.Contains(got, "<") {
			t.Errorf("stripEmail(%q) = %q still contains '<'", s, got)
		}
		if len(got) > len(s) {
			t.Errorf("stripEmail(%q) = %q grew", s, got)
		}
	})
}

func FuzzTruncateRunes(f *testing.F) {
	f.Add("short", 256)
	f.Add(strings.Repeat("é", 300), 256)
	f.Add("abc", 0)
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 4096 {
			return
		}
		got := truncateRunes(s, n)
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Errorf("truncateRunes(%q, %d) = %q split a character", s, n, got)
		}
		if utf8.RuneCountInString(got) > n {
			t.Errorf("truncateRunes(%q, %d) = %q is too long", s, n, got)
		}
		if !strings.HasPrefix(s, got) {
			t.Errorf("truncateRunes(%q, %d) = %q is not a prefix", s, n, got)
		}
	})
}
