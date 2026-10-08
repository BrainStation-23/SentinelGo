//go:build linux

package gpu

// Hermetic tests for the Linux GPU collection pipeline. Every external
// dependency is replaced: gpuRunCommand returns fixture output for exactly the
// commands a test expects (anything else fails as "not installed"), and
// gpuSysfsRoot points at a fake sysfs tree in t.TempDir(). Nothing here reads
// the host's real /sys or runs lspci/nvidia-smi/rocm-smi.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// stubLinuxGPUCommands replaces gpuRunCommand with a lookup into outputs,
// keyed by the full space-joined command line. Unknown commands fail.
func stubLinuxGPUCommands(t *testing.T, outputs map[string]string) {
	t.Helper()
	orig := gpuRunCommand
	t.Cleanup(func() { gpuRunCommand = orig })
	gpuRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		if out, ok := outputs[key]; ok {
			return out, nil
		}
		return "", errors.New("command not available: " + key)
	}
}

// stubLinuxGPUSysfs points gpuSysfsRoot at a fresh empty directory and
// returns it so the test can populate a fake sysfs tree.
func stubLinuxGPUSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	orig := gpuSysfsRoot
	t.Cleanup(func() { gpuSysfsRoot = orig })
	gpuSysfsRoot = root
	return root
}

func writeLinuxGPUFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// addDRMCard creates <root>/class/drm/<card>/device as a symlink to a PCI
// device directory named after busID (mirroring the real sysfs layout) and
// optionally writes mem_info_vram_total inside it.
func addDRMCard(t *testing.T, root, card, busID, vramTotal string) {
	t.Helper()
	devDir := filepath.Join(root, "devices", "pci0000:00", busID)
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if vramTotal != "" {
		writeLinuxGPUFile(t, filepath.Join(devDir, "mem_info_vram_total"), vramTotal)
	}
	cardDir := filepath.Join(root, "class", "drm", card)
	if err := os.MkdirAll(cardDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(devDir, filepath.Join(cardDir, "device")); err != nil {
		t.Fatal(err)
	}
}

const (
	nvidiaSMIArgs = "nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits --id=0000:"
	rocmShowBus   = "rocm-smi --showbus --csv"
)

func TestGetGPUs_LspciUnavailable(t *testing.T) {
	stubLinuxGPUSysfs(t)
	stubLinuxGPUCommands(t, nil)
	if got := getGPUs(); len(got) != 0 {
		t.Fatalf("getGPUs() = %+v, want none when lspci fails", got)
	}
}

func TestGetGPUs_MixedVendors(t *testing.T) {
	root := stubLinuxGPUSysfs(t)

	// AMD: VRAM via DRM sysfs. Surround it with entries the scan must skip.
	addDRMCard(t, root, "card1", "0000:03:00.0", "8589934592\n")
	addDRMCard(t, root, "card0", "0000:00:02.0", "")
	if err := os.MkdirAll(filepath.Join(root, "class", "drm", "card1-DP-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "class", "drm", "renderD128"), 0o755); err != nil {
		t.Fatal(err)
	}
	// NVIDIA's out-of-tree module exposes a version file.
	writeLinuxGPUFile(t, filepath.Join(root, "module", "nvidia", "version"), "535.104.05\n")
	// Intel: hardware ID from the PCI uevent.
	writeLinuxGPUFile(t, filepath.Join(root, "bus", "pci", "devices", "0000:00:02.0", "uevent"),
		"DRIVER=i915\nPCI_CLASS=30000\nPCI_ID=8086:3E92\nPCI_SUBSYS_ID=1028:0869\n")

	stubLinuxGPUCommands(t, map[string]string{
		"lspci -nn": "00:00.0 Host bridge [0600]: Intel Corporation 8th Gen Core Processor Host Bridge [8086:3ec2] (rev 07)\n" +
			"00:02.0 VGA compatible controller [0300]: Intel Corporation UHD Graphics 630 [8086:3e92]\n" +
			"\n" +
			"01:00.0 3D controller [0302]: NVIDIA Corporation GA102 [GeForce RTX 3080] [10de:2206] (rev a1)\n" +
			"03:00.0 Display controller [0380]: Advanced Micro Devices, Inc. [AMD/ATI] Navi 21 [Radeon RX 6800 XT] [1002:73bf] (rev c1)\n" +
			"04:00.0 Ethernet controller [0200]: Realtek RTL8111 [10ec:8168] (rev 15)\n",
		"lspci -v -s 01:00.0": "01:00.0 3D controller: NVIDIA Corporation GA102 (rev a1)\n" +
			"\tMemory at f6000000 (32-bit, non-prefetchable) [size=16M]\n" +
			"\tMemory at e0000000 (64-bit, prefetchable) [size=256M]\n" +
			"\tMemory at c0000000 (64-bit, prefetchable) [size=8G]\n" +
			"\tMemory at d0000000 (64-bit, prefetchable) [size=32M]\n" +
			"\tKernel driver in use: nvidia\n" +
			"\tKernel modules: nouveau, nvidia_drm, nvidia\n",
		nvidiaSMIArgs + "01:00.0": "NVIDIA GeForce RTX 3080, 10240, 535.104.05\n",
		"lspci -v -s 03:00.0": "03:00.0 Display controller: AMD Navi 21\n" +
			"\tKernel driver in use: amdgpu\n",
		// Intel lspci -v intentionally missing: fields stay Unknown.
	})

	gpus := getGPUs()
	if len(gpus) != 3 {
		t.Fatalf("got %d GPUs, want 3: %+v", len(gpus), gpus)
	}

	intel, nv, amd := gpus[0], gpus[1], gpus[2]

	if intel.Manufacturer != "Intel" || intel.Name != "Intel Corporation UHD Graphics 630" ||
		intel.Architecture != "Integrated" || intel.HardwareID != "8086:3E92" ||
		intel.DedicatedVRAM != "Unknown" || intel.CurrentStatus != "Unknown" || intel.DriverVersion != "Unknown" {
		t.Errorf("intel GPU = %+v", intel)
	}

	if nv.Manufacturer != "NVIDIA" || nv.Name != "NVIDIA GeForce RTX 3080" || nv.Chipset != nv.Name ||
		nv.DedicatedVRAM != "10240 MiB" || nv.DriverVersion != "535.104.05" ||
		nv.CurrentStatus != "OK" || nv.Architecture != "Discrete" || nv.HardwareID != "10de:2206" {
		t.Errorf("nvidia GPU = %+v", nv)
	}

	if amd.Manufacturer != "AMD" || amd.DedicatedVRAM != "8 GB" || amd.Architecture != "Discrete" ||
		amd.CurrentStatus != "OK" || amd.HardwareID != "1002:73bf" || amd.DriverVersion != "Unknown" {
		t.Errorf("amd GPU = %+v", amd)
	}
}

func TestQueryLinuxPCIDetails(t *testing.T) {
	stubLinuxGPUSysfs(t)
	stubLinuxGPUCommands(t, map[string]string{
		"lspci -v -s 01:00.0": "\tMemory at e0000000 (64-bit, prefetchable) [size=256M]\n" +
			"\tMemory at c0000000 (64-bit, prefetchable) [size=8G]\n" +
			"\tMemory at d0000000 (64-bit, prefetchable) [size=32M]\n" +
			"\tKernel driver in use: nouveau\n",
	})

	vram, status, driver := queryLinuxPCIDetails("01:00.0")
	if vram != "8G" || status != "OK" || driver != "nouveau" {
		t.Errorf("queryLinuxPCIDetails = (%q, %q, %q), want (8G, OK, nouveau)", vram, status, driver)
	}

	vram, status, driver = queryLinuxPCIDetails("09:00.0")
	if vram != "Unknown" || status != "Unknown" || driver != "" {
		t.Errorf("queryLinuxPCIDetails on failure = (%q, %q, %q), want (Unknown, Unknown, \"\")", vram, status, driver)
	}
}

func TestEnrichNvidiaGPU(t *testing.T) {
	cases := []struct {
		name       string
		out        string
		available  bool
		wantName   string
		wantVRAM   string
		wantDriver string
	}{
		{"nvidia-smi missing keeps lspci data", "", false, "lspci name", "Unknown", "Unknown"},
		{"all fields", "Tesla T4, 15360, 550.54.15\nTesla T4, 15360, 550.54.15\n", true, "Tesla T4", "15360 MiB", "550.54.15"},
		{"name only", "Quadro P400\n", true, "Quadro P400", "Unknown", "Unknown"},
		{"empty output keeps lspci data", "\n", true, "lspci name", "Unknown", "Unknown"},
		{"empty memory field skipped", "A100, , 535.0\n", true, "A100", "Unknown", "535.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outputs := map[string]string{}
			if c.available {
				outputs[nvidiaSMIArgs+"01:00.0"] = c.out
			}
			stubLinuxGPUCommands(t, outputs)
			g := newUnknownLinuxGPU()
			g.Name = "lspci name"
			enrichNvidiaGPU(&g, "01:00.0")
			if g.Name != c.wantName || g.DedicatedVRAM != c.wantVRAM || g.DriverVersion != c.wantDriver {
				t.Errorf("got name=%q vram=%q driver=%q, want %q %q %q",
					g.Name, g.DedicatedVRAM, g.DriverVersion, c.wantName, c.wantVRAM, c.wantDriver)
			}
		})
	}
}

func TestEnrichAMDGPU_ROCmFallback(t *testing.T) {
	const header = "device,PCI Bus\n"
	cases := []struct {
		name     string
		outputs  map[string]string
		wantVRAM string
	}{
		{
			name: "rocm-smi reports VRAM for matching bus (with PCI domain)",
			outputs: map[string]string{
				rocmShowBus: header + "card0,0000:01:00.0\n\ncard1,0000:03:00.0\n",
				"rocm-smi -d 1 --showmeminfo vram --csv": "device,VRAM Total Memory (B)\n" +
					"\ncard1,8589934592\n",
			},
			wantVRAM: "8 GB",
		},
		{
			name: "rocm-smi bus without domain, GPU[n] device field",
			outputs: map[string]string{
				rocmShowBus:                              header + "GPU[2],03:00.0\n",
				"rocm-smi -d 2 --showmeminfo vram --csv": "device,VRAM Total Memory (B)\nbogus\nGPU[2],17163091968\n",
			},
			wantVRAM: "15 GB",
		},
		{
			name:     "rocm-smi not installed",
			outputs:  nil,
			wantVRAM: "Unknown",
		},
		{
			name:     "no bus matches",
			outputs:  map[string]string{rocmShowBus: header + "card0,0000:01:00.0\nnocomma\n"},
			wantVRAM: "Unknown",
		},
		{
			name:     "matching row without device index",
			outputs:  map[string]string{rocmShowBus: header + "cardX,03:00.0\n"},
			wantVRAM: "Unknown",
		},
		{
			name:     "meminfo command fails",
			outputs:  map[string]string{rocmShowBus: header + "card0,03:00.0\n"},
			wantVRAM: "Unknown",
		},
		{
			name: "meminfo value not numeric",
			outputs: map[string]string{
				rocmShowBus:                              header + "card0,03:00.0\n",
				"rocm-smi -d 0 --showmeminfo vram --csv": "device,VRAM Total Memory (B)\ncard0,N/A\n",
			},
			wantVRAM: "Unknown",
		},
		{
			name: "meminfo header only",
			outputs: map[string]string{
				rocmShowBus:                              header + "card0,03:00.0\n",
				"rocm-smi -d 0 --showmeminfo vram --csv": "device,VRAM Total Memory (B)\n",
			},
			wantVRAM: "Unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubLinuxGPUSysfs(t) // no DRM tree: forces the rocm-smi path
			stubLinuxGPUCommands(t, c.outputs)
			g := newUnknownLinuxGPU()
			enrichAMDGPU(&g, "03:00.0")
			if g.DedicatedVRAM != c.wantVRAM {
				t.Errorf("DedicatedVRAM = %q, want %q", g.DedicatedVRAM, c.wantVRAM)
			}
		})
	}
}

func TestLinuxSysfsVRAMBytes(t *testing.T) {
	t.Run("drm dir missing", func(t *testing.T) {
		stubLinuxGPUSysfs(t)
		if got := linuxSysfsVRAMBytes("03:00.0"); got != 0 {
			t.Errorf("got %d, want 0", got)
		}
	})

	cases := []struct {
		name  string
		vram  string
		bus   string
		query string
		want  int64
	}{
		{"matching card", "4294967296\n", "0000:03:00.0", "03:00.0", 4294967296},
		{"bus match is case-insensitive", "1024", "0000:0a:00.0", "0A:00.0", 1024},
		{"different bus", "1024", "0000:04:00.0", "03:00.0", 0},
		{"no vram file", "", "0000:03:00.0", "03:00.0", 0},
		{"garbage vram", "lots", "0000:03:00.0", "03:00.0", 0},
		{"zero vram", "0", "0000:03:00.0", "03:00.0", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := stubLinuxGPUSysfs(t)
			addDRMCard(t, root, "card0", c.bus, c.vram)
			// A card directory without a device link must be skipped, not fatal.
			// Connector outputs and render nodes are not cards and are skipped.
			for _, d := range []string{"card9", "card0-HDMI-A-1", "renderD128"} {
				if err := os.MkdirAll(filepath.Join(root, "class", "drm", d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if got := linuxSysfsVRAMBytes(c.query); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestEnrichIntelGPU(t *testing.T) {
	t.Run("uevent missing leaves HardwareID", func(t *testing.T) {
		stubLinuxGPUSysfs(t)
		g := newUnknownLinuxGPU()
		g.HardwareID = "8086:3e92"
		enrichIntelGPU(&g, "00:02.0")
		if g.HardwareID != "8086:3e92" {
			t.Errorf("HardwareID = %q", g.HardwareID)
		}
	})
	t.Run("uevent without PCI_ID leaves HardwareID", func(t *testing.T) {
		root := stubLinuxGPUSysfs(t)
		writeLinuxGPUFile(t, filepath.Join(root, "bus", "pci", "devices", "0000:00:02.0", "uevent"), "DRIVER=i915\n")
		g := newUnknownLinuxGPU()
		enrichIntelGPU(&g, "00:02.0")
		if g.HardwareID != "Unknown" {
			t.Errorf("HardwareID = %q, want Unknown", g.HardwareID)
		}
	})
}

func TestLinuxDriverVersionFromSysfs(t *testing.T) {
	root := stubLinuxGPUSysfs(t)
	writeLinuxGPUFile(t, filepath.Join(root, "module", "nvidia", "version"), "  550.54.15 \n")
	if got := linuxDriverVersionFromSysfs("nvidia"); got != "550.54.15" {
		t.Errorf("nvidia version = %q", got)
	}
	if got := linuxDriverVersionFromSysfs("i915"); got != "" {
		t.Errorf("built-in module version = %q, want empty", got)
	}
	if got := linuxDriverVersionFromSysfs(""); got != "" {
		t.Errorf("empty driver = %q, want empty", got)
	}
}

func TestBuildLinuxGPU_Rejects(t *testing.T) {
	stubLinuxGPUSysfs(t)
	stubLinuxGPUCommands(t, nil)
	if _, ok := buildLinuxGPU("04:00.0 Ethernet controller [0200]: Realtek RTL8111 [10ec:8168]"); ok {
		t.Error("non-GPU line accepted")
	}
	// A GPU class line without a ": " description has no name.
	if g, ok := buildLinuxGPU("00:02.0 VGA compatible controller"); ok {
		t.Errorf("nameless GPU accepted: %+v", g)
	}
	// VMware SVGA: unknown vendor, no enrichment.
	g, ok := buildLinuxGPU("00:0f.0 VGA compatible controller [0300]: VMware SVGA II Adapter [15ad:0405]")
	if !ok || g.Manufacturer != "Unknown" || g.Architecture != "Unknown" || g.HardwareID != "15ad:0405" {
		t.Errorf("VMware GPU = %+v, ok=%v", g, ok)
	}
}

func TestFirstIntInString(t *testing.T) {
	cases := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"GPU[0]", 0, true},
		{"card12", 12, true},
		{"7", 7, true},
		{"", 0, false},
		{"cardX", 0, false},
		// A leading run that overflows int is skipped in favour of the next run.
		{"x99999999999999999999999y3", 3, true},
		{"99999999999999999999999", 0, false},
	}
	for _, c := range cases {
		got, ok := firstIntInString(c.in)
		// The int is meaningless when ok is false (Atoi may return a clamped value).
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("firstIntInString(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestRocmBusMatches(t *testing.T) {
	cases := []struct {
		line, bus, wantDev string
		wantOK             bool
	}{
		{"card0,0000:03:00.0", "03:00.0", "card0", true},
		{" GPU[1] , 03:00.0 ", "03:00.0", "GPU[1]", true},
		{"card0,0000:04:00.0", "03:00.0", "", false},
		{"no-comma", "03:00.0", "", false},
	}
	for _, c := range cases {
		dev, ok := rocmBusMatches(c.line, c.bus)
		if dev != c.wantDev || ok != c.wantOK {
			t.Errorf("rocmBusMatches(%q, %q) = (%q, %v), want (%q, %v)", c.line, c.bus, dev, ok, c.wantDev, c.wantOK)
		}
	}
}

func TestLspciHelpers(t *testing.T) {
	if hw, rest, ok := extractLspciHardwareID("No brackets here"); ok || hw != "" || rest != "No brackets here" {
		t.Errorf("extractLspciHardwareID without brackets = (%q, %q, %v)", hw, rest, ok)
	}
	if hw, rest, ok := extractLspciHardwareID("Broken [10de:2206"); ok || hw != "" || rest != "Broken [10de:2206" {
		t.Errorf("extractLspciHardwareID unterminated = (%q, %q, %v)", hw, rest, ok)
	}
	if got := stripLspciRevSuffix("GeForce (rev a1)"); got != "GeForce" {
		t.Errorf("stripLspciRevSuffix = %q", got)
	}
	if got := stripLspciRevSuffix("GeForce"); got != "GeForce" {
		t.Errorf("stripLspciRevSuffix no rev = %q", got)
	}
	if _, ok := extractPrefetchableSize("Memory at f6000000 (32-bit, non-prefetchable)"); ok {
		t.Error("extractPrefetchableSize accepted a line without [size=]")
	}
	if _, ok := extractPrefetchableSize("Memory at e0000000 (64-bit, prefetchable) [size=256M"); ok {
		t.Error("extractPrefetchableSize accepted an unterminated [size=")
	}
	if _, ok := extractKernelDriver("Kernel modules: nouveau"); ok {
		t.Error("extractKernelDriver accepted a Kernel modules line")
	}
	var g shared.GPU
	if _, g = parseLspciLine(""); g.Name != "Unknown" {
		t.Errorf("parseLspciLine(\"\") name = %q", g.Name)
	}
}
