//go:build darwin

package display

import "testing"

func TestCleanMacVendorName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Apple (0x106b)", "Apple"},
		{"NVIDIA (0x10de)", "NVIDIA"},
		{"AMD (0x1002)", "AMD"},
		{"Intel", "Intel"},
		{"Unknown (0x1234)", ""},
		{"", ""},
		{"Dell Inc.", "Dell Inc."},
		// sppci_vendor_ prefix (modern format)
		{"sppci_vendor_Apple", "Apple"},
		{"sppci_vendor_AMD", "AMD"},
		{"sppci_vendor_Intel", "Intel"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := cleanMacVendorName(tc.input)
			if got != tc.want {
				t.Errorf("cleanMacVendorName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseResolutionAndRefreshRate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantRes string
		wantHz  float64
	}{
		{"with Hz", "2560 x 1440 @ 60.00Hz", "2560x1440", 60.00},
		{"Retina no Hz", "3456 x 2160 Retina", "3456x2160", 0},
		{"bare dimensions", "1920 x 1080", "1920x1080", 0},
		{"fractional Hz", "2560 x 1440 @ 59.99Hz", "2560x1440", 59.99},
		{"4K 120Hz", "3840 x 2160 @ 120.00Hz", "3840x2160", 120.00},
		{"combined @Hz token", "1920 x 1080 @60Hz", "1920x1080", 60.0},
		{"empty input", "", "", 0},
		{"Hz only no resolution", "@ 60.00Hz", "", 60.00},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, hz := parseResolutionAndRefreshRate(tc.input)
			if res != tc.wantRes {
				t.Errorf("resolution = %q, want %q (input %q)", res, tc.wantRes, tc.input)
			}
			if hz != tc.wantHz {
				t.Errorf("refreshRate = %v, want %v (input %q)", hz, tc.wantHz, tc.input)
			}
		})
	}
}

func TestMacDisplayConnectionType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"spdisplays_internal", "Internal"},
		{"spdisplays_displayport", "DisplayPort"},
		{"spdisplays_hdmi", "HDMI"},
		{"spdisplays_vga", "VGA"},
		{"spdisplays_dvi", "DVI"},
		{"spdisplays_thunderbolt", "Thunderbolt"},
		{"spdisplays_usb-c", "USB"},
		{"spdisplays_unknown_type", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := macDisplayConnectionType(tc.input)
			if got != tc.want {
				t.Errorf("macDisplayConnectionType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseMacDisplayType(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"spdisplays_built-in-liquid-retina-xdr", []string{"Built-In", "Liquid Retina XDR"}},
		{"spdisplays_built-in-retina-xdr", []string{"Built-In", "Retina XDR"}},
		{"spdisplays_built-in-retina", []string{"Built-In", "Retina"}},
		{"spdisplays_built-in", []string{"Built-In"}},
		{"spdisplays_external", []string{"External"}},
		{"", nil},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseMacDisplayType(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseMacDisplayType(%q) = %v, want %v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("parseMacDisplayType(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestBuildMacDisplay_ModernFormat(t *testing.T) {
	// Mirrors the real system_profiler output structure for an Apple M2 Pro built-in display
	dm := map[string]any{
		"_name":                             "Color LCD",
		"_spdisplays_display-serial-number": "fd626d62",
		"_spdisplays_display-year":          "0",
		"_spdisplays_pixels":                "3024 x 1964",
		"_spdisplays_resolution":            "1512 x 982 @ 120.00Hz",
		"spdisplays_connection_type":        "spdisplays_internal",
		"spdisplays_display_type":           "spdisplays_built-in-liquid-retina-xdr",
	}
	d, ok := buildMacDisplay(dm, "Apple")
	if !ok {
		t.Fatal("buildMacDisplay returned ok=false")
	}
	if d.Resolution != "3024x1964" {
		t.Errorf("Resolution = %q, want %q", d.Resolution, "3024x1964")
	}
	if d.RefreshRate != 120.0 {
		t.Errorf("RefreshRate = %v, want 120.0", d.RefreshRate)
	}
	if d.SerialNumber != "fd626d62" {
		t.Errorf("SerialNumber = %q, want %q", d.SerialNumber, "fd626d62")
	}
	if d.ConnectionType != "Internal" {
		t.Errorf("ConnectionType = %q, want %q", d.ConnectionType, "Internal")
	}
	if d.Manufacturer != "Apple" {
		t.Errorf("Manufacturer = %q, want %q", d.Manufacturer, "Apple")
	}
	if len(d.MonitorType) == 0 {
		t.Error("MonitorType is empty, want at least one tag")
	}
	if d.Year != 0 {
		t.Errorf("Year = %d, want 0 (built-in has year=0, should be skipped)", d.Year)
	}
}

func TestGetDisplays_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	displays := getDisplays()
	for i, d := range displays {
		if d.Description == "" {
			t.Errorf("display[%d] has empty Description", i)
		}
		if d.Model == "" {
			t.Errorf("display[%d] %q has empty Model", i, d.Description)
		}
		t.Logf("display[%d]: desc=%q mfr=%q model=%q serial=%q size=%.1f\" refresh=%.2fHz conn=%q res=%q year=%d type=%v",
			i, d.Description, d.Manufacturer, d.Model, d.SerialNumber,
			d.Size, d.RefreshRate, d.ConnectionType, d.Resolution, d.Year, d.MonitorType)
	}
	t.Logf("total displays: %d", len(displays))
}
