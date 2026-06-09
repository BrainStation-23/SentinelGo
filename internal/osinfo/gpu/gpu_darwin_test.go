package gpu

import (
	"testing"
)

func TestMacGPUVendorFromStr(t *testing.T) {
	tests := []struct {
		name      string
		vendorStr string
		wantMfr   string
		wantArch  string
	}{
		// Standard system_profiler vendor strings with PCI ID suffix
		{"Apple with PCI ID", "Apple (0x106b)", "Apple", "Integrated"},
		{"Intel with PCI ID", "Intel (0x8086)", "Intel", "Integrated"},
		{"AMD with PCI ID", "AMD (0x1002)", "AMD", "Discrete"},
		{"NVIDIA with PCI ID", "NVIDIA (0x10de)", "NVIDIA", "Discrete"},

		// Alternate forms seen in the wild
		{"ATI Technologies", "ATI Technologies Inc.", "AMD", "Discrete"},
		{"Advanced Micro Devices long", "Advanced Micro Devices, Inc.", "AMD", "Discrete"},
		{"Intel Corporation", "Intel Corporation", "Intel", "Integrated"},

		// Passthrough for genuinely unknown vendors
		{"Unknown brand passes through", "Imagination Technologies", "Imagination Technologies", "Unknown"},

		// Edge cases
		{"empty string", "", "Unknown", "Unknown"},
		{"whitespace only trips strip", "Unknown (0x0000)", "Unknown", "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMfr, gotArch := macGPUVendorFromStr(tc.vendorStr)
			if gotMfr != tc.wantMfr {
				t.Errorf("macGPUVendorFromStr(%q) manufacturer = %q, want %q", tc.vendorStr, gotMfr, tc.wantMfr)
			}
			if gotArch != tc.wantArch {
				t.Errorf("macGPUVendorFromStr(%q) architecture = %q, want %q", tc.vendorStr, gotArch, tc.wantArch)
			}
		})
	}
}

func TestGetGPUs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	gpus := Get()
	if len(gpus) == 0 {
		t.Fatal("Get() returned no GPUs")
	}
	for i, g := range gpus {
		if g.Name == "" || g.Name == "Unknown" {
			t.Errorf("GPU[%d].Name is empty or Unknown", i)
		}
		t.Logf("gpu[%d]: name=%q manufacturer=%q arch=%q vram=%q status=%q",
			i, g.Name, g.Manufacturer, g.Architecture, g.DedicatedVRAM, g.CurrentStatus)
	}
}
