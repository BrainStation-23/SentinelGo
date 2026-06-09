package security

import (
	"strings"
	"testing"
)

func TestKnownAVServices(t *testing.T) {
	seen := map[string]bool{}
	for _, svc := range knownAVServices {
		if svc.service == "" {
			t.Errorf("empty service name for %q", svc.name)
		}
		if svc.name == "" {
			t.Errorf("empty display name for service %q", svc.service)
		}
		seen[svc.service] = true
	}
	// Ensure expected services are present.
	required := []string{"clamav-daemon", "falcon-sensor", "cbsensor"}
	for _, r := range required {
		if !seen[r] {
			t.Errorf("expected service %q not found in knownAVServices", r)
		}
	}
}

func TestKernelLockdownParsing(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"none [integrity] confidentiality", "integrity"},
		{"[none] integrity confidentiality", "none"},
		{"none integrity [confidentiality]", "confidentiality"},
		{"none integrity confidentiality", "unknown"},
	}
	for _, c := range cases {
		got := "unknown"
		for _, mode := range []string{"confidentiality", "integrity", "none"} {
			if strings.Contains(c.content, "["+mode+"]") {
				got = mode
				break
			}
		}
		if got != c.want {
			t.Errorf("content=%q: got %q, want %q", c.content, got, c.want)
		}
	}
}
