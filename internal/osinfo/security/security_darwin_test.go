package security

import (
	"strings"
	"testing"
)

func TestParseAllowUSBRestrictedJSON(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"allowed true → enabled", `{"allowUSBRestricted":true}`, "enabled"},
		{"allowed false → disabled", `{"allowUSBRestricted":false}`, "disabled"},
		{"key absent → empty", `{"otherKey":true}`, ""},
		{"empty object → empty", `{}`, ""},
		{"invalid json → empty", `not json`, ""},
		{"wrong value type → empty", `{"allowUSBRestricted":"yes"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseAllowUSBRestrictedJSON(c.input)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestKnownAVApps(t *testing.T) {
	for _, app := range knownAVApps {
		if app.path == "" {
			t.Errorf("empty path for AV app %q", app.name)
		}
		if app.name == "" {
			t.Errorf("empty name for AV path %q", app.path)
		}
	}
}

func TestCollectSecureBootParsing(t *testing.T) {
	cases := []struct {
		output string
		want   string
	}{
		{"Boot Policy: Full Security", "enabled"},
		{"Boot Policy: Reduced Security", "enabled"},
		{"Boot Policy: No Security", "disabled"},
		{"Apple T2 Security Chip\n  Bridge OS Version: 17.4", "enabled"},
		{"Intel Mac without T2", "unknown"},
	}
	for _, c := range cases {
		lower := strings.ToLower(c.output)
		got := "unknown"
		if strings.Contains(lower, "no security") {
			got = "disabled"
		} else if strings.Contains(lower, "full security") || strings.Contains(lower, "reduced security") {
			got = "enabled"
		} else if strings.Contains(lower, "bridge os") || strings.Contains(lower, "apple t") {
			got = "enabled"
		}
		if got != c.want {
			t.Errorf("output=%q: got %q, want %q", c.output, got, c.want)
		}
	}
}

func TestCollectSIPParsing(t *testing.T) {
	cases := []struct {
		output string
		want   string
	}{
		{"System Integrity Protection status: enabled.", "enabled"},
		{"System Integrity Protection status: disabled.", "disabled"},
		{"", "unknown"},
	}
	for _, c := range cases {
		lower := strings.ToLower(strings.TrimSpace(c.output))
		got := "unknown"
		if strings.Contains(lower, "enabled") {
			got = "enabled"
		} else if strings.Contains(lower, "disabled") {
			got = "disabled"
		}
		if got != c.want {
			t.Errorf("output=%q: got %q, want %q", c.output, got, c.want)
		}
	}
}
