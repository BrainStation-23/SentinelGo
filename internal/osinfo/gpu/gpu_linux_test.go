package gpu

import (
	"testing"
)

func TestParsePCISize(t *testing.T) {
	const (
		KB = int64(1024)
		MB = 1024 * KB
		GB = 1024 * MB
	)

	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512K", "512K", 512 * KB},
		{"256M", "256M", 256 * MB},
		{"8G", "8G", 8 * GB},
		{"4G", "4G", 4 * GB},
		{"empty string", "", 0},
		{"non-numeric", "abc", 0},
		{"no suffix is bare int", "1024", 1024},
		{"whitespace trimmed", "  128M  ", 128 * MB},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePCISize(tc.input)
			if got != tc.want {
				t.Errorf("parsePCISize(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestLinuxGPUManufacturer(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want string
	}{
		{"NVIDIA RTX", "NVIDIA GeForce RTX 3080", "NVIDIA"},
		{"AMD Radeon", "AMD Radeon RX 6800 XT", "AMD"},
		{"Radeon without AMD prefix", "Radeon HD 7970", "AMD"},
		{"Advanced Micro Devices long name", "Advanced Micro Devices, Inc. [AMD/ATI] Vega 10 XL", "AMD"},
		{"Intel UHD", "Intel Corporation UHD Graphics 620", "Intel"},
		{"Intel Arc", "Intel Corporation Arc A770", "Intel"},
		{"VMware SVGA unknown", "VMware SVGA II Adapter", "Unknown"},
		{"empty string", "", "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := linuxGPUManufacturer(tc.desc)
			if got != tc.want {
				t.Errorf("linuxGPUManufacturer(%q) = %q, want %q", tc.desc, got, tc.want)
			}
		})
	}
}

func TestLinuxGPUArchitecture(t *testing.T) {
	tests := []struct {
		name         string
		manufacturer string
		gpuName      string
		hasVRAM      bool
		want         string
	}{
		// NVIDIA is always discrete regardless of VRAM detection
		{"NVIDIA with VRAM", "NVIDIA", "GeForce RTX 3080", true, "Discrete"},
		{"NVIDIA without VRAM", "NVIDIA", "GeForce RTX 3080", false, "Discrete"},

		// Intel: integrated unless name contains "arc"
		{"Intel UHD integrated", "Intel", "UHD Graphics 620", false, "Integrated"},
		{"Intel Arc discrete", "Intel", "Arc A770", false, "Discrete"},
		{"Intel Arc capitalization", "Intel", "Intel Arc A380", false, "Discrete"},

		// AMD: discrete when VRAM was found, integrated (APU) otherwise
		{"AMD with VRAM = Discrete", "AMD", "Radeon RX 6800 XT", true, "Discrete"},
		{"AMD without VRAM = APU", "AMD", "Radeon Vega 8 Graphics", false, "Integrated"},

		// Unknown manufacturer
		{"unknown manufacturer", "Unknown", "VMware SVGA", false, "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := linuxGPUArchitecture(tc.manufacturer, tc.gpuName, tc.hasVRAM)
			if got != tc.want {
				t.Errorf("linuxGPUArchitecture(%q, %q, %v) = %q, want %q",
					tc.manufacturer, tc.gpuName, tc.hasVRAM, got, tc.want)
			}
		})
	}
}

func TestFormatLinuxVRAM(t *testing.T) {
	const (
		MB = int64(1024 * 1024)
		GB = 1024 * MB
	)

	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"512 MB", 512 * MB, "512 MB"},
		{"1023 MB rounds down", 1023 * MB, "1023 MB"},
		{"1 GB", 1 * GB, "1 GB"},
		{"8 GB", 8 * GB, "8 GB"},
		{"16 GB", 16 * GB, "16 GB"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatLinuxVRAM(tc.bytes)
			if got != tc.want {
				t.Errorf("formatLinuxVRAM(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestGetGPUs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	gpus := Get()
	// lspci may return nothing in a container/VM without a PCI GPU; don't fatal.
	for i, g := range gpus {
		if g.Name == "" {
			t.Errorf("GPU[%d].Name is empty", i)
		}
		t.Logf("gpu[%d]: name=%q manufacturer=%q arch=%q vram=%q driver=%q",
			i, g.Name, g.Manufacturer, g.Architecture, g.DedicatedVRAM, g.DriverVersion)
	}
	t.Logf("total GPUs found: %d", len(gpus))
}
