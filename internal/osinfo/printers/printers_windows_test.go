//go:build windows

package printers

import (
	"testing"
)

func TestParseWindowsPrinterJSON(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
		wantBW    map[string]bool // names expected to be "Black and white"
		wantDPI   map[string]int  // name → expected HorizontalDPI
	}{
		{
			name:      "empty/invalid JSON",
			input:     "",
			wantNames: nil,
		},
		{
			name:      "single printer object (not array)",
			input:     `{"Name":"HP LaserJet","DriverName":"HP LaserJet 1020 Driver","Type":0}`,
			wantNames: []string{"HP LaserJet"},
			wantBW:    map[string]bool{"HP LaserJet": true},
		},
		{
			name: "array of printers",
			input: `[
				{"Name":"Inkjet Pro","DriverName":"Inkjet Driver","Type":0},
				{"Name":"Laser Mono","DriverName":"Mono Laser 600dpi","Type":0}
			]`,
			wantNames: []string{"Inkjet Pro", "Laser Mono"},
			wantBW:    map[string]bool{"Laser Mono": true},
			wantDPI:   map[string]int{"Laser Mono": 600},
		},
		{
			name:      "1200 dpi driver",
			input:     `[{"Name":"Sharp 1200","DriverName":"Sharp 1200dpi Laser","Type":0}]`,
			wantNames: []string{"Sharp 1200"},
			wantBW:    map[string]bool{"Sharp 1200": true},
			wantDPI:   map[string]int{"Sharp 1200": 1200},
		},
		{
			name:      "360 dpi driver",
			input:     `[{"Name":"Old Printer","DriverName":"360dpi Color","Type":0}]`,
			wantNames: []string{"Old Printer"},
			wantDPI:   map[string]int{"Old Printer": 360},
		},
		{
			name: "duplicate names deduplicated",
			input: `[
				{"Name":"Alpha","DriverName":"Driver","Type":0},
				{"Name":"Alpha","DriverName":"Driver","Type":0}
			]`,
			wantNames: []string{"Alpha"},
		},
		{
			name:      "item without Name field is skipped",
			input:     `[{"DriverName":"Driver","Type":0}]`,
			wantNames: nil,
		},
		{
			name:      "seen map filters existing name",
			input:     `[{"Name":"Existing","DriverName":"Driver","Type":0}]`,
			wantNames: nil, // caller pre-populates seen with "Existing"
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			if tc.name == "seen map filters existing name" {
				seen["Existing"] = true
			}
			got := parseWindowsPrinterJSON(tc.input, seen)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d printers, want %d; got %v", len(got), len(tc.wantNames), got)
			}
			for i, p := range got {
				if p.Description != tc.wantNames[i] {
					t.Errorf("[%d] Description = %q, want %q", i, p.Description, tc.wantNames[i])
				}
				if tc.wantBW[p.Description] && p.PrintingType != "Black and white" {
					t.Errorf("[%d] %q: PrintingType = %q, want %q", i, p.Description, p.PrintingType, "Black and white")
				}
				if !tc.wantBW[p.Description] && p.PrintingType != "Colorful" {
					t.Errorf("[%d] %q: PrintingType = %q, want Colorful", i, p.Description, p.PrintingType)
				}
				if expected, ok := tc.wantDPI[p.Description]; ok {
					if p.PrintingResolution.HorizontalDPI != expected {
						t.Errorf("[%d] %q: HorizontalDPI = %d, want %d", i, p.Description, p.PrintingResolution.HorizontalDPI, expected)
					}
					if p.PrintingResolution.VerticalDPI != expected {
						t.Errorf("[%d] %q: VerticalDPI = %d, want %d", i, p.Description, p.PrintingResolution.VerticalDPI, expected)
					}
				}
			}
		})
	}
}

func TestParseWMICPrinterOutput(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
	}{
		{
			name:      "empty output",
			input:     "",
			wantNames: nil,
		},
		{
			name:      "header and separator lines are skipped",
			input:     "Name                Status\n===                ======\n",
			wantNames: nil,
		},
		{
			name:      "single printer",
			input:     "HP OfficeJet  Online\n",
			wantNames: []string{"HP OfficeJet"},
		},
		{
			name:      "blank lines are skipped",
			input:     "\nHP OfficeJet  Online\n\n",
			wantNames: []string{"HP OfficeJet"},
		},
		{
			name:      "duplicate deduplicated",
			input:     "HP OfficeJet  Online\nHP OfficeJet  Online\n",
			wantNames: []string{"HP OfficeJet"},
		},
		{
			name:      "seen map filters existing name",
			input:     "Existing  Online\n",
			wantNames: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			if tc.name == "seen map filters existing name" {
				seen["Existing"] = true
			}
			got := parseWMICPrinterOutput(tc.input, seen)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d printers, want %d; got %v", len(got), len(tc.wantNames), got)
			}
			for i, p := range got {
				if p.Description != tc.wantNames[i] {
					t.Errorf("[%d] Description = %q, want %q", i, p.Description, tc.wantNames[i])
				}
				if p.PrintingType != "Colorful" {
					t.Errorf("[%d] PrintingType = %q, want Colorful", i, p.PrintingType)
				}
			}
		})
	}
}
