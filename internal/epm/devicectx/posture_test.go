package devicectx

import "testing"

func TestNormalizeDiskEncryption(t *testing.T) {
	cases := map[string]string{
		"Encrypted":           "encrypted",
		"Unencrypted":         "unencrypted",
		"Partially Encrypted": "partial",
		"Unknown":             "unknown",
		"":                    "unknown",
		"garbage":             "unknown",
	}
	for in, want := range cases {
		if got := normalizeDiskEncryption(in); got != want {
			t.Errorf("normalizeDiskEncryption(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeFirewallState(t *testing.T) {
	cases := map[string]string{
		"Enabled":           "enabled",
		"Disabled":          "disabled",
		"Partially Enabled": "partial",
		"Unknown":           "unknown",
		"":                  "unknown",
	}
	for in, want := range cases {
		if got := normalizeFirewallState(in); got != want {
			t.Errorf("normalizeFirewallState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeAntivirusHealth(t *testing.T) {
	cases := map[string]string{
		"Healthy":   "healthy",
		"Unhealthy": "unhealthy",
		"None":      "none",
		"Unknown":   "unknown",
		"":          "unknown",
	}
	for in, want := range cases {
		if got := normalizeAntivirusHealth(in); got != want {
			t.Errorf("normalizeAntivirusHealth(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeEnabledVocab(t *testing.T) {
	cases := map[string]string{
		"Enabled":     "enabled",
		"Disabled":    "disabled",
		"Unsupported": "unsupported",
		"Unknown":     "unknown",
		"":            "unknown",
	}
	for in, want := range cases {
		if got := normalizeEnabledVocab(in); got != want {
			t.Errorf("normalizeEnabledVocab(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCollectPostureReal_DoesNotPanic is a smoke test: security.Collect()
// swallows its own probe failures (see its doc comment), so the only thing
// worth asserting cross-platform in CI is that wiring it up end to end
// through collectPostureReal never panics and always returns a nil error —
// the actual field VALUES it produces are inherently host-dependent and
// covered instead by the pure normalize* table tests above.
func TestCollectPostureReal_DoesNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("security.Collect() makes real OS probes and can take tens of seconds; skipped under -short")
	}
	res := collectPostureReal()
	if res.err != nil {
		t.Errorf("collectPostureReal() returned non-nil error %v; security.Collect() never errors", res.err)
	}
}
