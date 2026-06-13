//go:build darwin

package printers

import (
	"testing"
)

func TestParseSystemProfilerPrinters(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []struct{ desc, printType string }
	}{
		{
			name:  "empty output",
			input: "",
			want:  nil,
		},
		{
			name: "single printer with explicit type",
			input: `Printers:

    HP OfficeJet Pro:
      Name: HP OfficeJet Pro
      Type: Bonjour
      URI: ipp://hp-officejet.local/ipp/print
`,
			want: []struct{ desc, printType string }{
				{"HP OfficeJet Pro", "Bonjour"},
			},
		},
		{
			name: "type line with empty value defaults to Colorful",
			input: `    Canon Printer:
      Name: Canon Printer
      Type:
`,
			want: []struct{ desc, printType string }{
				{"Canon Printer", "Colorful"},
			},
		},
		{
			name: "Name without following Type is not emitted",
			input: `    Ghost Printer:
      Name: Ghost Printer
      URI: socket://192.168.1.99
`,
			want: nil,
		},
		{
			name: "duplicate names deduplicated via seen",
			input: `      Name: Alpha
      Type: USB
`,
			want: nil, // seen already has "Alpha"
		},
		{
			name: "multiple printers",
			input: `      Name: Printer One
      Type: AirPrint
      Name: Printer Two
      Type: USB
`,
			want: []struct{ desc, printType string }{
				{"Printer One", "AirPrint"},
				{"Printer Two", "USB"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			if tc.name == "duplicate names deduplicated via seen" {
				seen["Alpha"] = true
			}
			got := parseSystemProfilerPrinters(tc.input, seen)
			if len(got) != len(tc.want) {
				t.Fatalf("parseSystemProfilerPrinters returned %d printers, want %d", len(got), len(tc.want))
			}
			for i, p := range got {
				if p.Description != tc.want[i].desc {
					t.Errorf("[%d] Description = %q, want %q", i, p.Description, tc.want[i].desc)
				}
				if p.PrintingType != tc.want[i].printType {
					t.Errorf("[%d] PrintingType = %q, want %q", i, p.PrintingType, tc.want[i].printType)
				}
			}
		})
	}
}
