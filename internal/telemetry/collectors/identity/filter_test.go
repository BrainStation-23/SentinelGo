package identity

import "testing"

func TestIsPlaceholder(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"To Be Filled By O.E.M.", true},
		{"  Default String  ", true},
		{"", true},
		{"   ", true},
		{"0123456789", true},
		{"00000000-0000-0000-0000-000000000000", true},
		{"SN-ABC123", false},
		{"Dell Inc.", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := isPlaceholder(tc.input); got != tc.want {
				t.Errorf("isPlaceholder(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestClean(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  Dell Inc.  ", "Dell Inc."},
		{"To be filled by O.E.M.", ""},
		{"", ""},
		{"SN-123", "SN-123"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := clean(tc.input); got != tc.want {
				t.Errorf("clean(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
