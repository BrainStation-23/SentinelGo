package ram

import (
	"testing"
)

func TestNormalizeRAMManufacturer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Filter cases — meaningless sentinels
		{"empty string", "", ""},
		{"Unknown", "Unknown", ""},
		{"UNKNOWN upper", "UNKNOWN", ""},
		{"Not Provided", "Not Provided", ""},
		{"Not Specified", "Not Specified", ""},
		{"Not Applicable", "Not Applicable", ""},
		{"whitespace only", "   ", ""},

		// Known vendor substring matching
		{"samsung lowercase", "samsung", "Samsung"},
		{"Samsung mixed", "Samsung Electronics", "Samsung"},
		{"hynix", "SK hynix", "SK Hynix"},
		{"Hynix alone", "Hynix", "SK Hynix"},
		{"micron", "Micron Technology", "Micron"},
		{"MICRON upper", "MICRON", "Micron"},
		{"kingston", "Kingston Technology", "Kingston"},
		{"corsair", "Corsair Memory", "Corsair"},
		{"crucial", "Crucial CT16G4S266M", "Crucial"},
		{"g.skill dot", "G.Skill", "G.Skill"},
		{"gskill nospace", "GSkill", "G.Skill"},
		{"patriot", "Patriot Memory", "Patriot"},
		{"teamgroup", "TeamGroup", "Team Group"},
		{"team group space", "Team Group", "Team Group"},
		{"adata", "ADATA Technology", "ADATA"},
		{"a-data hyphen", "A-DATA", "ADATA"},
		{"transcend", "Transcend Information", "Transcend"},
		{"nanya", "Nanya Technology", "Nanya"},
		{"ramaxel", "Ramaxel Technology", "Ramaxel"},
		{"infineon", "Infineon Technologies", "Infineon"},

		// Passthrough — unknown real brands should not be dropped
		{"SomeBrandX passthrough", "SomeBrandX", "SomeBrandX"},
		// JEDEC-looking hex codes should pass through unchanged
		{"JEDEC hex code", "04CE", "04CE"},
		{"hex with 0x prefix", "0xCE00", "0xCE00"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeRAMManufacturer(tc.input)
			if got != tc.want {
				t.Errorf("normalizeRAMManufacturer(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseMemorySize(t *testing.T) {
	const (
		KB = uint64(1024)
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"8 GB", "8 GB", 8 * GB},
		{"4096 MB equals 4 GB", "4096 MB", 4096 * MB},
		{"1 TB", "1 TB", 1 * TB},
		{"512 KB", "512 KB", 512 * KB},
		{"16 GB", "16 GB", 16 * GB},
		{"32 GB lowercase", "32 gb", 32 * GB},
		{"2048 mb", "2048 mb", 2048 * MB},
		// Edge cases
		{"zero string", "0", 0},
		{"empty string", "", 0},
		{"non-numeric", "No Module Installed", 0},
		{"negative value", "-8 GB", 0},
		// No unit — defaults to GB
		{"bare number defaults to GB", "8", 8 * GB},
		// Fractional
		{"0.5 GB", "0.5 GB", uint64(0.5 * float64(GB))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMemorySize(tc.input)
			if got != tc.want {
				t.Errorf("parseMemorySize(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
