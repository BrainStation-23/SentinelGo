//go:build darwin

package software

// Fuzz targets for the macOS software metadata parsers. Bundle identifiers and
// signing names come from the app itself, and Homebrew metadata from the
// formula or cask author, so this output is untrusted input: parsing must never
// panic and must never attribute metadata to the wrong app.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzParseMdlsRaw$' -fuzztime=1m ./internal/service/software/

import (
	"strings"
	"testing"
)

func FuzzParseMdlsRaw(f *testing.F) {
	f.Add("2025-06-10 08:42:11 +0000\x002024-01-02 03:04:05 +0000\x00123\x00com.apple.Safari", uint8(1))
	f.Add("(null)\x00(null)\x00(null)\x00(null)\x00(null)\x00(null)\x00(null)\x00(null)\x00", uint8(2))
	f.Add("(null)\n(null)\n(null)\n(null)\n", uint8(1))
	f.Add("a\x00b\nc\x00d", uint8(1))
	f.Add("", uint8(0))
	f.Add("-1\x00x\x00-99\x00\x00", uint8(1))
	f.Fuzz(func(t *testing.T, out string, n uint8) {
		paths := make([]string, int(n%4))
		for i := range paths {
			paths[i] = "/Applications/App" + strings.Repeat("x", i) + ".app"
		}
		result := map[string]bundleMeta{}
		ok := parseMdlsRaw([]byte(out), paths, result)
		if !ok && len(result) != 0 {
			t.Errorf("rejected output still added %d entries", len(result))
		}
		if ok && len(result) != len(paths) {
			t.Errorf("accepted output gave %d entries for %d paths", len(result), len(paths))
		}
		for p, m := range result {
			if m.Size < 0 {
				t.Errorf("%s: negative size %d", p, m.Size)
			}
		}
	})
}

func FuzzParseHomebrewInfo(f *testing.F) {
	f.Add(`{"formulae":[{"name":"git","tap":"homebrew/core","installed":[{"time":1700000000}]}],"casks":[{"token":"docker","tap":"homebrew/cask","installed_time":1710000000}]}`)
	f.Add(`{"formulae":[{"name":"x","installed":[]}],"casks":null}`)
	f.Add(`{"formulae":"nope"}`)
	f.Add(`{"casks":[{"token":"t","installed_time":-1}]}`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, s string) {
		formulae, casks := parseHomebrewInfo([]byte(s))
		for _, m := range []map[string]brewMeta{formulae, casks} {
			for name, meta := range m {
				if meta.InstallDate != "" && !strings.HasSuffix(meta.InstallDate, "Z") {
					t.Errorf("%q: install date %q is not UTC RFC 3339", name, meta.InstallDate)
				}
			}
		}
	})
}

func FuzzMacPublisher(f *testing.F) {
	f.Add("identified_developer", "Developer ID Application: Google LLC (EQHXZ8M8AV)")
	f.Add("identified_developer", "Developer ID Application: (")
	f.Add("identified_developer", "Developer ID Application:  ()")
	f.Add("apple", "")
	f.Add("mac_app_store", "Apple Mac OS Application Signing")
	f.Fuzz(func(t *testing.T, from, leaf string) {
		got := macPublisher(from, []string{leaf})
		if got != "" && got != "Apple Inc." && !strings.Contains(leaf, got) {
			t.Errorf("macPublisher(%q, %q) = %q is not taken from the certificate", from, leaf, got)
		}
		if got != strings.TrimSpace(got) {
			t.Errorf("macPublisher(%q, %q) = %q has surrounding space", from, leaf, got)
		}
	})
}
