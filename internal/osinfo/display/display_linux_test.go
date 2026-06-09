//go:build linux

package display

import (
	"fmt"
	"testing"
)

// makeEDID builds a 128-byte EDID fixture with specified fields set.
// edid[8-9]:  manufacturer bytes b1/b2
// edid[16]:   week of manufacture
// edid[17]:   year of manufacture (value, add 1990 to get year)
// edid[21-22]: horizontal/vertical screen size in cm
// edid[54-71]: 18-byte preferred timing descriptor
// edid[72-89]: 18-byte monitor name descriptor (tag 0xFC)
// edid[90-107]: 18-byte serial descriptor (tag 0xFF)
func makeEDID(b1, b2, week, yearVal, hCm, vCm byte, timing [18]byte, modelName, serialStr string) []byte {
	edid := make([]byte, 128)
	copy(edid[0:8], []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00})
	edid[8] = b1
	edid[9] = b2
	edid[16] = week
	edid[17] = yearVal
	edid[21] = hCm
	edid[22] = vCm
	copy(edid[54:72], timing[:])

	// Monitor name descriptor at offset 72
	if modelName != "" {
		edid[75] = 0xFC
		payload := modelName + "\n"
		for i := 0; i < 13 && i < len(payload); i++ {
			edid[77+i] = payload[i]
		}
		for i := len(payload); i < 13; i++ {
			edid[77+i] = 0x20
		}
	}

	// Serial descriptor at offset 90
	if serialStr != "" {
		edid[93] = 0xFF
		payload := serialStr + "\n"
		for i := 0; i < 13 && i < len(payload); i++ {
			edid[95+i] = payload[i]
		}
		for i := len(payload); i < 13; i++ {
			edid[95+i] = 0x20
		}
	}

	return edid
}

// timing1920x1080 is the preferred timing block for 1920×1080.
// Pixel clock 148500 kHz / 10 = 14850 = 0x3A02 (LE: 0x02, 0x3A).
// H active=1920 (low=0x80, high-nib=7), H blank=280 (low=0x18, high-nib=1) → byte58=0x71
// V active=1080 (low=0x38, high-nib=4), V blank=30  (low=0x1E, high-nib=0) → byte61=0x40
var timing1920x1080 = [18]byte{0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x1E, 0x40}

func TestParseEDIDManufacturer(t *testing.T) {
	tests := []struct {
		name   string
		b1, b2 byte
		want   string
	}{
		// "DEL": D=4, E=5, L=12 → b1=(4<<2)|(5>>3)=0x10, b2=((5&7)<<5)|12=0xAC
		{"DEL (Dell)", 0x10, 0xAC, "DEL"},
		// "SAM": S=19, A=1, M=13 → b1=(19<<2)|(1>>3)=0x4C, b2=((1&7)<<5)|13=0x2D
		{"SAM (Samsung)", 0x4C, 0x2D, "SAM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			edid := make([]byte, 16)
			edid[8] = tc.b1
			edid[9] = tc.b2
			got := parseEDIDManufacturer(edid)
			if got != tc.want {
				t.Errorf("parseEDIDManufacturer(0x%02X, 0x%02X) = %q, want %q", tc.b1, tc.b2, got, tc.want)
			}
		})
	}

	t.Run("too short returns empty", func(t *testing.T) {
		if got := parseEDIDManufacturer([]byte{0x00, 0xFF}); got != "" {
			t.Errorf("expected empty for 2-byte input, got %q", got)
		}
	})
}

func TestParseEDIDModel(t *testing.T) {
	edid := makeEDID(0x10, 0xAC, 1, 30, 52, 29, [18]byte{}, "DELL U2722D", "")
	got := parseEDIDModel(edid)
	if got != "DELL U2722D" {
		t.Errorf("parseEDIDModel = %q, want %q", got, "DELL U2722D")
	}
}

func TestParseEDIDSerial(t *testing.T) {
	edid := makeEDID(0x10, 0xAC, 1, 30, 52, 29, [18]byte{}, "", "SN12345")
	got := parseEDIDSerial(edid)
	if got != "SN12345" {
		t.Errorf("parseEDIDSerial = %q, want %q", got, "SN12345")
	}
}

func TestParseEDIDSize(t *testing.T) {
	tests := []struct {
		hCm, vCm         byte
		wantMin, wantMax float64
	}{
		// 52 cm × 29 cm diagonal ≈ 23.4"
		{52, 29, 23.0, 24.0},
		// 60 cm × 34 cm diagonal ≈ 27.1"
		{60, 34, 26.5, 27.5},
		// zeros → 0
		{0, 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%dx%dcm", tc.hCm, tc.vCm), func(t *testing.T) {
			edid := makeEDID(0, 0, 0, 0, tc.hCm, tc.vCm, [18]byte{}, "", "")
			got := parseEDIDSize(edid)
			if tc.wantMin == 0 && tc.wantMax == 0 {
				if got != 0 {
					t.Errorf("parseEDIDSize = %v, want 0", got)
				}
				return
			}
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("parseEDIDSize = %.2f\", want %.2f\"–%.2f\"", got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestParseEDIDNativeResolution(t *testing.T) {
	t.Run("1920x1080", func(t *testing.T) {
		edid := makeEDID(0, 0, 0, 0, 0, 0, timing1920x1080, "", "")
		w, h := parseEDIDNativeResolution(edid)
		if w != 1920 || h != 1080 {
			t.Errorf("parseEDIDNativeResolution = (%d, %d), want (1920, 1080)", w, h)
		}
	})

	t.Run("2560x1440 timing", func(t *testing.T) {
		// Pixel clock irrelevant for this test — just needs to be non-zero.
		// H active=2560: low=0x00 (256%256=0), high-nib=10 → byte58 high=(10<<4)|...
		// Wait: 2560 = 0xA00 → low=0x00, high=0x0A
		// H blank=160: low=0xA0, high=0x00 → byte58=(0x0A<<4)|(0x00)=0xA0
		// V active=1440: low=0xA0 (1440%256=160=0xA0), high=0x05 (1440>>8=5)
		// V blank=30: low=0x1E, high=0x00 → byte61=(0x05<<4)|(0x00)=0x50
		timing := [18]byte{0x01, 0x00, 0x00, 0xA0, 0xA0, 0xA0, 0x1E, 0x50}
		edid := makeEDID(0, 0, 0, 0, 0, 0, timing, "", "")
		w, h := parseEDIDNativeResolution(edid)
		if w != 2560 || h != 1440 {
			t.Errorf("parseEDIDNativeResolution = (%d, %d), want (2560, 1440)", w, h)
		}
	})

	t.Run("zero clock returns 0,0", func(t *testing.T) {
		edid := makeEDID(0, 0, 0, 0, 0, 0, [18]byte{}, "", "")
		w, h := parseEDIDNativeResolution(edid)
		if w != 0 || h != 0 {
			t.Errorf("parseEDIDNativeResolution with zero clock = (%d, %d), want (0, 0)", w, h)
		}
	})

	t.Run("too short returns 0,0", func(t *testing.T) {
		w, h := parseEDIDNativeResolution([]byte{1, 2, 3})
		if w != 0 || h != 0 {
			t.Errorf("parseEDIDNativeResolution too short = (%d, %d), want (0, 0)", w, h)
		}
	})
}

func TestParseEDIDYear(t *testing.T) {
	tests := []struct {
		name     string
		yearByte byte
		want     int
	}{
		{"2020 (byte 30)", 30, 2020},
		{"2015 (byte 25)", 25, 2015},
		{"1990 (byte 0)", 0, 1990},
		{"2010 (byte 20)", 20, 2010},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			edid := make([]byte, 18)
			edid[17] = tc.yearByte
			got := parseEDIDYear(edid)
			if got != tc.want {
				t.Errorf("parseEDIDYear(byte=%d) = %d, want %d", tc.yearByte, got, tc.want)
			}
		})
	}

	t.Run("too short returns 0", func(t *testing.T) {
		if got := parseEDIDYear([]byte{0, 1, 2}); got != 0 {
			t.Errorf("parseEDIDYear too short = %d, want 0", got)
		}
	})
}

func TestLinuxConnectionType(t *testing.T) {
	tests := []struct {
		connectorName string
		want          string
	}{
		{"eDP-1", "Internal"},
		{"eDP-2", "Internal"},
		{"LVDS-1", "Internal"},
		{"DSI-0", "Internal"},
		{"HDMI-A-1", "HDMI"},
		{"HDMI-B-2", "HDMI"},
		{"DP-1", "DisplayPort"},
		{"DP-2", "DisplayPort"},
		{"DVI-D-1", "DVI"},
		{"DVI-A-1", "DVI"},
		{"VGA-1", "VGA"},
		{"WRITEBACK-0", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.connectorName, func(t *testing.T) {
			got := linuxConnectionType(tc.connectorName)
			if got != tc.want {
				t.Errorf("linuxConnectionType(%q) = %q, want %q", tc.connectorName, got, tc.want)
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
		if d.ConnectionType != "" {
			validConns := map[string]bool{
				"Internal": true, "DisplayPort": true, "HDMI": true,
				"VGA": true, "DVI": true,
			}
			if !validConns[d.ConnectionType] {
				t.Errorf("display[%d] ConnectionType = %q (unexpected value)", i, d.ConnectionType)
			}
		}
		t.Logf("display[%d]: desc=%q mfr=%q model=%q serial=%q size=%.1f\" refresh=%.2fHz conn=%q year=%d res=%q",
			i, d.Description, d.Manufacturer, d.Model, d.SerialNumber,
			d.Size, d.RefreshRate, d.ConnectionType, d.Year, d.Resolution)
	}
	t.Logf("total displays: %d", len(displays))
}
