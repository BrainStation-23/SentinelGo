package gpu

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
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

// stubDarwinGPUCommand replaces darwinRunCommand for the duration of the test.
// Commands are keyed by "name arg1 arg2 ..."; keys in failing return an error,
// keys in responses return their output, anything else fails as unexpected.
// The returned pointer records every command that was run.
func stubDarwinGPUCommand(t *testing.T, responses map[string]string, failing map[string]bool) *[]string {
	t.Helper()
	orig := darwinRunCommand
	var calls []string
	darwinRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, key)
		if failing[key] {
			return "", errors.New("command failed: " + key)
		}
		if out, ok := responses[key]; ok {
			return out, nil
		}
		return "", errors.New("unexpected command: " + key)
	}
	t.Cleanup(func() { darwinRunCommand = orig })
	return &calls
}

// unknownGPUWith returns newUnknownDarwinGPU() with mutate applied, so test
// expectations only spell out the fields that differ from the placeholders.
func unknownGPUWith(mutate func(g *shared.GPU)) shared.GPU {
	g := newUnknownDarwinGPU()
	mutate(&g)
	return g
}

func TestNewUnknownDarwinGPU(t *testing.T) {
	want := shared.GPU{
		Name: "Unknown", Manufacturer: "Unknown", Architecture: "Unknown", Chipset: "Unknown",
		DedicatedVRAM: "Unknown", SharedVRAM: "Unknown", DriverVersion: "Unknown",
		DriverDate: "Unknown", HardwareID: "Unknown", CurrentStatus: "unknown",
	}
	if got := newUnknownDarwinGPU(); !reflect.DeepEqual(got, want) {
		t.Errorf("newUnknownDarwinGPU() = %+v, want %+v", got, want)
	}
}

func TestParseDarwinDisplay(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   shared.GPU
		wantOK bool
	}{
		{
			name:   "not a map",
			input:  "spdisplays_display",
			want:   shared.GPU{},
			wantOK: false,
		},
		{
			name:   "empty map has no name",
			input:  map[string]any{},
			want:   newUnknownDarwinGPU(),
			wantOK: false,
		},
		{
			name: "Apple Silicon: no VRAM or PCI ID keys",
			input: map[string]any{
				"_name":             "Apple M2",
				"sppci_model":       "Apple M2",
				"spdisplays_vendor": "sppci_vendor_Apple",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Apple M2", "Apple M2"
				g.Manufacturer, g.Architecture = "Apple", "Integrated"
			}),
			wantOK: true,
		},
		{
			name: "Intel integrated with shared VRAM and PCI IDs",
			input: map[string]any{
				"_name":                  "Intel Iris Plus Graphics",
				"spdisplays_vendor":      "Intel (0x8086)",
				"spdisplays_vram_shared": "1536 MB",
				"spdisplays_vendor_id":   "0x8086",
				"spdisplays_device_id":   "0x8a53",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Intel Iris Plus Graphics", "Intel Iris Plus Graphics"
				g.Manufacturer, g.Architecture = "Intel", "Integrated"
				g.SharedVRAM = "1536 MB"
				g.HardwareID = "0x8086:0x8a53"
			}),
			wantOK: true,
		},
		{
			name: "integrated GPU reporting only spdisplays_vram uses it as shared",
			input: map[string]any{
				"_name":             "Intel UHD Graphics 630",
				"spdisplays_vendor": "Intel",
				"spdisplays_vram":   "1536 MB",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Intel UHD Graphics 630", "Intel UHD Graphics 630"
				g.Manufacturer, g.Architecture = "Intel", "Integrated"
				g.SharedVRAM = "1536 MB"
			}),
			wantOK: true,
		},
		{
			name: "integrated GPU keeps spdisplays_vram_shared over spdisplays_vram",
			input: map[string]any{
				"_name":                  "Intel HD Graphics",
				"spdisplays_vendor":      "Intel (0x8086)",
				"spdisplays_vram_shared": "1 GB",
				"spdisplays_vram":        "2 GB",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Intel HD Graphics", "Intel HD Graphics"
				g.Manufacturer, g.Architecture = "Intel", "Integrated"
				g.SharedVRAM = "1 GB"
			}),
			wantOK: true,
		},
		{
			name: "AMD discrete with dedicated VRAM and vendor ID only",
			input: map[string]any{
				"_name":                "AMD Radeon Pro 5500M",
				"spdisplays_vendor":    "AMD (0x1002)",
				"spdisplays_vram":      "8 GB",
				"spdisplays_vendor_id": "0x1002",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "AMD Radeon Pro 5500M", "AMD Radeon Pro 5500M"
				g.Manufacturer, g.Architecture = "AMD", "Discrete"
				g.DedicatedVRAM = "8 GB"
				g.HardwareID = "0x1002"
			}),
			wantOK: true,
		},
		{
			name: "unknown vendor with VRAM is refined to Discrete",
			input: map[string]any{
				"_name":             "Mystery GPU",
				"spdisplays_vendor": "Imagination",
				"spdisplays_vram":   "512 MB",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Mystery GPU", "Mystery GPU"
				g.Manufacturer, g.Architecture = "Imagination", "Discrete"
				g.DedicatedVRAM = "512 MB"
			}),
			wantOK: true,
		},
		{
			name: "non-string shared VRAM still marks Integrated; device ID alone is ignored",
			input: map[string]any{
				"_name":                  "Odd GPU",
				"spdisplays_vram_shared": float64(1536),
				"spdisplays_device_id":   "0x1234",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Name, g.Chipset = "Odd GPU", "Odd GPU"
				g.Architecture = "Integrated"
			}),
			wantOK: true,
		},
		{
			name: "non-string name is ignored",
			input: map[string]any{
				"_name":             42.0,
				"spdisplays_vendor": "NVIDIA (0x10de)",
			},
			want: unknownGPUWith(func(g *shared.GPU) {
				g.Manufacturer, g.Architecture = "NVIDIA", "Discrete"
			}),
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDarwinDisplay(tc.input)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseDarwinDisplay() =\n  %+v\nwant\n  %+v", got, tc.want)
			}
		})
	}
}

const darwinGPUCmd = "system_profiler SPDisplaysDataType -json"

func TestGetGPUs_DarwinStubbed(t *testing.T) {
	const fixture = `{
  "SPDisplaysDataType" : [
    {
      "_name" : "Intel UHD Graphics 630",
      "spdisplays_vendor" : "Intel (0x8086)",
      "spdisplays_vram_shared" : "1536 MB",
      "spdisplays_vendor_id" : "0x8086",
      "spdisplays_device_id" : "0x3e9b"
    },
    "not-a-display-map",
    {
      "spdisplays_vendor" : "Apple (0x106b)"
    },
    {
      "_name" : "AMD Radeon Pro 5500M",
      "spdisplays_vendor" : "AMD (0x1002)",
      "spdisplays_vram" : "8 GB",
      "spdisplays_vendor_id" : "0x1002",
      "spdisplays_device_id" : "0x7340"
    }
  ]
}`
	calls := stubDarwinGPUCommand(t, map[string]string{darwinGPUCmd: fixture}, nil)

	gpus := Get()

	want := []shared.GPU{
		unknownGPUWith(func(g *shared.GPU) {
			g.Name, g.Chipset = "Intel UHD Graphics 630", "Intel UHD Graphics 630"
			g.Manufacturer, g.Architecture = "Intel", "Integrated"
			g.SharedVRAM = "1536 MB"
			g.HardwareID = "0x8086:0x3e9b"
		}),
		unknownGPUWith(func(g *shared.GPU) {
			g.Name, g.Chipset = "AMD Radeon Pro 5500M", "AMD Radeon Pro 5500M"
			g.Manufacturer, g.Architecture = "AMD", "Discrete"
			g.DedicatedVRAM = "8 GB"
			g.HardwareID = "0x1002:0x7340"
		}),
	}
	if !reflect.DeepEqual(gpus, want) {
		t.Errorf("Get() =\n  %+v\nwant\n  %+v", gpus, want)
	}
	if len(*calls) != 1 || (*calls)[0] != darwinGPUCmd {
		t.Errorf("commands run = %q, want [%q]", *calls, darwinGPUCmd)
	}
}

func TestGetGPUs_DarwinFailureModes(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		cmdFail bool
	}{
		{name: "command fails", cmdFail: true},
		{name: "invalid JSON", output: "system_profiler: not json"},
		{name: "missing SPDisplaysDataType key", output: `{"SPOtherDataType": []}`},
		{name: "SPDisplaysDataType is not an array", output: `{"SPDisplaysDataType": {"_name": "x"}}`},
		{name: "empty display list", output: `{"SPDisplaysDataType": []}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubDarwinGPUCommand(t,
				map[string]string{darwinGPUCmd: tc.output},
				map[string]bool{darwinGPUCmd: tc.cmdFail})
			if gpus := getGPUs(); len(gpus) != 0 {
				t.Errorf("getGPUs() = %+v, want empty", gpus)
			}
		})
	}
}
