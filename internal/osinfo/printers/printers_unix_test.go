//go:build linux || darwin

package printers

import (
	"testing"
)

func TestParseLpstat(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   []string // expected printer names in order
		bwName string   // name that should be classified as black-and-white (if any)
	}{
		{
			name:  "empty output",
			input: "",
			want:  nil,
		},
		{
			name: "single colorful printer",
			input: `printer HP_OfficeJet is idle. enabled since Tue 01 Jan 2025 00:00:00
`,
			want: []string{"HP_OfficeJet"},
		},
		{
			name: "laser printer gets black and white type",
			input: `printer Brother_laser is idle. enabled since Tue 01 Jan 2025 00:00:00
`,
			want:   []string{"Brother_laser"},
			bwName: "Brother_laser",
		},
		{
			name: "mono printer gets black and white type",
			input: `printer Canon_mono is idle. enabled since Tue 01 Jan 2025 00:00:00
`,
			want:   []string{"Canon_mono"},
			bwName: "Canon_mono",
		},
		{
			name: "non-printer lines are skipped",
			input: `system default destination: HP_OfficeJet
printer HP_OfficeJet is idle. enabled since Tue 01 Jan 2025 00:00:00
`,
			want: []string{"HP_OfficeJet"},
		},
		{
			name: "multiple printers, duplicates deduplicated",
			input: `printer Alpha is idle. enabled since Tue 01 Jan 2025 00:00:00
printer Beta is idle. enabled since Tue 01 Jan 2025 00:00:00
printer Alpha is idle. enabled since Tue 01 Jan 2025 00:00:00
`,
			want: []string{"Alpha", "Beta"},
		},
		{
			name: "line with fewer than 2 fields is skipped",
			input: `printer
printer HP is idle.
`,
			want: []string{"HP"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			got := parseLpstat(tc.input, seen)

			if len(got) != len(tc.want) {
				t.Fatalf("parseLpstat returned %d printers, want %d; got %v", len(got), len(tc.want), got)
			}
			for i, p := range got {
				if p.Description != tc.want[i] {
					t.Errorf("[%d] Description = %q, want %q", i, p.Description, tc.want[i])
				}
				if tc.bwName == p.Description && p.PrintingType != "Black and white" {
					t.Errorf("[%d] %q: PrintingType = %q, want %q", i, p.Description, p.PrintingType, "Black and white")
				}
				if tc.bwName == "" && p.PrintingType != "Colorful" {
					t.Errorf("[%d] %q: PrintingType = %q, want Colorful", i, p.Description, p.PrintingType)
				}
			}
		})
	}
}
