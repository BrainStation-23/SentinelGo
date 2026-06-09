package gpu

import (
	"testing"
)

func TestFormatVRAMBytes(t *testing.T) {
	const (
		MB = int64(1024 * 1024)
		GB = 1024 * MB
	)
	// uint32Near4GB = 4*GB - MB
	const near4GB = 4*GB - MB

	tests := []struct {
		name  string
		input int64
		want  string
	}{
		{"1 KB", 1024, "1 KB"},
		{"512 MB", 512 * MB, "512 MB"},
		{"1 GB", 1 * GB, "1 GB"},
		{"2 GB", 2 * GB, "2 GB"},
		{"4 GB minus 1 MB overflows uint32 boundary", near4GB, ">= 4 GB"},
		{"uint32 max (4294967295) is reported as overflow", 4294967295, ">= 4 GB"},
		// Cards over 4 GB overflow the WMI uint32 field and show as large near-max numbers.
		{"8 GB card overflows uint32", 8*GB - 1, ">= 4 GB"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatVRAMBytes(tc.input)
			if got != tc.want {
				t.Errorf("formatVRAMBytes(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestWindowsGPUArchitecture(t *testing.T) {
	tests := []struct {
		name         string
		vmt          int
		manufacturer string
		want         string
	}{
		// VideoMemoryType takes priority
		{"vmt 3 = Discrete", 3, "Intel Corporation", "Discrete"},
		{"vmt 4 = Integrated", 4, "NVIDIA", "Integrated"},

		// Ambiguous/absent vmt falls back to manufacturer
		{"vmt 0 Intel → Integrated", 0, "Intel Corporation", "Integrated"},
		{"vmt 1 Intel → Integrated", 1, "Intel Corporation", "Integrated"},
		{"vmt 0 NVIDIA → Discrete", 0, "NVIDIA", "Discrete"},
		{"vmt 2 AMD → Discrete", 2, "Advanced Micro Devices, Inc.", "Discrete"},
		{"vmt 0 ATI → Discrete", 0, "ATI Technologies Inc.", "Discrete"},
		{"vmt 0 apple → Integrated", 0, "Apple Inc.", "Integrated"},
		{"vmt 0 unknown mfr → Unknown", 0, "VMware", "Unknown"},
		{"vmt 0 empty mfr → Unknown", 0, "", "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsGPUArchitecture(tc.vmt, tc.manufacturer)
			if got != tc.want {
				t.Errorf("windowsGPUArchitecture(%d, %q) = %q, want %q", tc.vmt, tc.manufacturer, got, tc.want)
			}
		})
	}
}

func TestGetGPUs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	gpus := Get()
	// On a real Windows machine there is always at least one GPU.
	if len(gpus) == 0 {
		t.Fatal("Get() returned no GPUs")
	}
	for i, g := range gpus {
		if g.Name == "" || g.Name == "Unknown" {
			t.Errorf("GPU[%d].Name is empty or Unknown", i)
		}
		t.Logf("gpu[%d]: name=%q manufacturer=%q arch=%q vram=%q status=%q driver=%q",
			i, g.Name, g.Manufacturer, g.Architecture, g.DedicatedVRAM, g.CurrentStatus, g.DriverVersion)
	}
}
