package osdetail

import "testing"

func TestActivationStatusName(t *testing.T) {
	tests := []struct {
		status uint32
		want   string
	}{
		{0, "unlicensed"},
		{1, "licensed"},
		{2, "out_of_box_grace"},
		{3, "out_of_tolerance_grace"},
		{4, "non_genuine_grace"},
		{5, "notification"},
		{6, "extended_grace"},
		{99, "unknown"},
	}
	for _, tc := range tests {
		if got := activationStatusName(tc.status); got != tc.want {
			t.Errorf("activationStatusName(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestEarliestUnixTime(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantFound bool
		want      int64
	}{
		{"multiple values", "1700000000\n1600000000\n1800000000\n", true, 1600000000},
		{"single value", "1700000000", true, 1700000000},
		{"blank lines mixed in", "\n1700000000\n\n1650000000\n\n", true, 1650000000},
		{"unparseable lines skipped", "not-a-number\n1700000000\n", true, 1700000000},
		{"all unparseable", "not-a-number\nalso-not\n", false, 0},
		{"empty", "", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, found := earliestUnixTime(tc.output)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if found && got != tc.want {
				t.Errorf("earliest = %d, want %d", got, tc.want)
			}
		})
	}
}
