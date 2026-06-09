//go:build windows

package display

import "testing"

func TestWmiByteArrayToString(t *testing.T) {
	tests := []struct {
		name string
		b    []int32
		want string
	}{
		{"ascii string", []int32{'D', 'E', 'L', 'L', 0}, "DELL"},
		{"trailing spaces trimmed", []int32{' ', 'D', 'E', 'L', ' ', 0}, "DEL"},
		{"stops at first null", []int32{0, 'A', 'B'}, ""},
		{"empty input", []int32{}, ""},
		{"all zeros", []int32{0, 0, 0}, ""},
		{"model with spaces", []int32{'U', '2', '7', '2', '2', 'D', 0}, "U2722D"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wmiByteArrayToString(tc.b)
			if got != tc.want {
				t.Errorf("wmiByteArrayToString(%v) = %q, want %q", tc.b, got, tc.want)
			}
		})
	}
}

func TestVideoOutputTechToString(t *testing.T) {
	tests := []struct {
		tech uint32
		want string
	}{
		{0, "VGA"},
		{4, "DVI"},
		{5, "HDMI"},
		{10, "DisplayPort"},
		{11, "DisplayPort Embedded"},
		{15, "Miracast"},
		{0x80000000, "Internal"},
		{0xFFFFFFFF, "Other"},
		{0xFFFFFFFE, "Uninitialized"},
		{0x42, "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := videoOutputTechToString(tc.tech)
			if got != tc.want {
				t.Errorf("videoOutputTechToString(%d) = %q, want %q", tc.tech, got, tc.want)
			}
		})
	}
}

func TestInstanceSerial(t *testing.T) {
	input := `DISPLAY\GSMA3421\4&1c63dbb0&0&UID4357`
	s1 := instanceSerial(input)
	s2 := instanceSerial(input)

	if s1 != s2 {
		t.Errorf("instanceSerial is not deterministic: %q != %q", s1, s2)
	}
	if len(s1) != 16 {
		t.Errorf("instanceSerial len = %d, want 16", len(s1))
	}

	other := instanceSerial(`DISPLAY\OTHER\different_instance`)
	if s1 == other {
		t.Errorf("instanceSerial should differ for different inputs")
	}
}

func TestFormatResolution(t *testing.T) {
	tests := []struct {
		name   string
		width  uint32
		height uint32
		want   string
	}{
		{"1080p", 1920, 1080, "1920x1080"},
		{"1440p", 2560, 1440, "2560x1440"},
		{"4K", 3840, 2160, "3840x2160"},
		{"zero width", 0, 1080, ""},
		{"zero height", 1920, 0, ""},
		{"both zero", 0, 0, ""},
		{"1200p", 1920, 1200, "1920x1200"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatResolution(tc.width, tc.height)
			if got != tc.want {
				t.Errorf("formatResolution(%d, %d) = %q, want %q", tc.width, tc.height, got, tc.want)
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
		if d.Year < 0 {
			t.Errorf("display[%d] Year = %d, want >= 0", i, d.Year)
		}
		t.Logf("display[%d]: desc=%q mfr=%q model=%q serial=%q size=%.1f\" refresh=%.2fHz conn=%q year=%d res=%q",
			i, d.Description, d.Manufacturer, d.Model, d.SerialNumber,
			d.Size, d.RefreshRate, d.ConnectionType, d.Year, d.Resolution)
	}
	t.Logf("total displays: %d", len(displays))
}
