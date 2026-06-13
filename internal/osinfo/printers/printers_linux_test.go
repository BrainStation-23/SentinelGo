//go:build linux

package printers

import (
	"testing"
)

func TestParseCupsPrintersConf(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty content",
			input: "",
			want:  nil,
		},
		{
			name: "single printer with DeviceURI",
			input: `<Printer HP_OfficeJet>
DeviceURI ipp://192.168.1.10/ipp/print
</Printer>
`,
			want: []string{"HP_OfficeJet"},
		},
		{
			name: "printer section without DeviceURI is not emitted",
			input: `<Printer NoURI>
Info Some printer
</Printer>
`,
			want: nil,
		},
		{
			name: "multiple printers",
			input: `<Printer Alpha>
DeviceURI socket://192.168.1.1
</Printer>
<Printer Beta>
DeviceURI socket://192.168.1.2
</Printer>
`,
			want: []string{"Alpha", "Beta"},
		},
		{
			name: "duplicate printer names deduplicated via seen",
			input: `<Printer Alpha>
DeviceURI socket://192.168.1.1
</Printer>
`,
			want: nil, // seen already contains "Alpha"
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			if tc.name == "duplicate printer names deduplicated via seen" {
				seen["Alpha"] = true
			}
			got := parseCupsPrintersConf(tc.input, seen)
			if len(got) != len(tc.want) {
				t.Fatalf("parseCupsPrintersConf returned %d printers, want %d; got %v", len(got), len(tc.want), got)
			}
			for i, p := range got {
				if p.Description != tc.want[i] {
					t.Errorf("[%d] Description = %q, want %q", i, p.Description, tc.want[i])
				}
				if p.PrintingType != "Colorful" {
					t.Errorf("[%d] PrintingType = %q, want Colorful", i, p.PrintingType)
				}
			}
		})
	}
}
