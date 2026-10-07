//go:build darwin

package display

// Fuzz target for the macOS system_profiler display parsers. The refresh rate
// is a float64 in the heartbeat payload, so it must stay finite: encoding/json
// cannot marshal NaN or Inf and would fail the whole payload.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (macOS).
// To fuzz: go test -run='^$' -fuzz='^FuzzDarwinDisplayParsers$' -fuzztime=1m ./internal/osinfo/display/

import (
	"math"
	"regexp"
	"testing"
	"unicode/utf8"
)

var darwinResolutionRe = regexp.MustCompile(`^[0-9]+x[0-9]+$`)

func FuzzDarwinDisplayParsers(f *testing.F) {
	for _, s := range []string{
		"2560 x 1440 @ 60.00Hz", "3456 x 2160 Retina", "1920 x 1080 @ NaNHz", "1 x 1 @ InfHz",
		"-5 x +5", "x", "x 1", "1 x", "@Hz", "Hz",
		"spdisplays_built-in-liquid-retina-xdr", "spdisplays_external", "spdisplays_über-display",
		"spdisplays_-", "spdisplays_", "", "\xff-\xfe",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		res, rate := parseResolutionAndRefreshRate(s)
		if res != "" && !darwinResolutionRe.MatchString(res) {
			t.Fatalf("resolution = %q, want WxH", res)
		}
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
			t.Fatalf("refreshRate = %v, want finite and >= 0", rate)
		}
		for _, tag := range parseMacDisplayType(s) {
			if utf8.ValidString(s) && !utf8.ValidString(tag) {
				t.Fatalf("parseMacDisplayType(%q) produced invalid UTF-8 tag %q", s, tag)
			}
		}
	})
}
