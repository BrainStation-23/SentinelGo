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
		t.Logf("display[%d]: desc=%q mfr=%q model=%q serial=%q size=%.1f\" refresh=%.2fHz conn=%q res=%q",
			i, d.Description, d.Manufacturer, d.Model, d.SerialNumber,
			d.Size, d.RefreshRate, d.ConnectionType, d.Resolution)
	}
	t.Logf("total displays: %d", len(displays))
}
