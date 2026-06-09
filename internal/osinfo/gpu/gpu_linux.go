package gpu

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// parsePCISize converts lspci size strings like "256M", "8G", "512K" to bytes.
func parsePCISize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mul := int64(1)
	last := s[len(s)-1]
	switch last {
	case 'K':
		mul = 1024
		s = s[:len(s)-1]
	case 'M':
		mul = 1024 * 1024
		s = s[:len(s)-1]
	case 'G':
		mul = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n * mul
}

// linuxGPUManufacturer extracts a canonical GPU manufacturer from an lspci description.
func linuxGPUManufacturer(desc string) string {
	nameLow := strings.ToLower(desc)
	switch {
	case strings.Contains(nameLow, "nvidia"):
		return "NVIDIA"
	case strings.Contains(nameLow, "amd") ||
		strings.Contains(nameLow, "radeon") ||
		strings.Contains(nameLow, "advanced micro devices"):
		return "AMD"
	case strings.Contains(nameLow, "intel"):
		return "Intel"
	}
	return "Unknown"
}

// linuxGPUArchitecture returns "Discrete" or "Integrated".
// hasVRAM should be true when a dedicated VRAM size was successfully determined.
func linuxGPUArchitecture(manufacturer, name string, hasVRAM bool) string {
	switch manufacturer {
	case "NVIDIA":
		return "Discrete"
	case "Intel":
		if strings.Contains(strings.ToLower(name), "arc") {
			return "Discrete"
		}
		return "Integrated"
	case "AMD":
		if hasVRAM {
			return "Discrete"
		}
		return "Integrated"
	}
	return "Unknown"
}

// formatLinuxVRAM converts raw VRAM bytes to a human-readable string.
func formatLinuxVRAM(bytes int64) string {
	if bytes >= 1024*1024*1024 {
		return strconv.FormatInt(bytes/(1024*1024*1024), 10) + " GB"
	}
	return strconv.FormatInt(bytes/(1024*1024), 10) + " MB"
}

// linuxSysfsVRAMBytes reads the total VRAM in bytes for the GPU at busID from the DRM sysfs.
// The AMD amdgpu driver exposes this at /sys/class/drm/cardN/device/mem_info_vram_total.
// Returns 0 when unavailable (driver doesn't expose the file, integrated GPU, or any error).
func linuxSysfsVRAMBytes(busID string) int64 {
	const drmBase = "/sys/class/drm"
	entries, err := os.ReadDir(drmBase)
	if err != nil {
		return 0
	}
	busLow := strings.ToLower(busID)
	for _, e := range entries {
		name := e.Name()
		// Skip render nodes (renderD*) and display outputs (card0-HDMI-A-1, etc.)
		if !strings.HasPrefix(name, "card") || strings.Contains(name, "-") {
			continue
		}
		// /sys/class/drm/cardN/device symlink resolves to something ending "0000:BB:DD.F"
		target, err := os.Readlink(drmBase + "/" + name + "/device")
		if err != nil {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(target), busLow) {
			continue
		}
		raw, err := shared.ReadFileContent(drmBase + "/" + name + "/device/mem_info_vram_total")
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		return n
	}
	return 0
}

// findROCmDeviceIndex maps a PCI bus ID (e.g. "01:00.0") to a rocm-smi device
// index so VRAM can be queried per-GPU rather than from a global dump.
func findROCmDeviceIndex(busID string) int {
	out, err := shared.RunCommand("rocm-smi", "--showbus", "--csv")
	if err != nil {
		return -1
	}
	busLow := strings.ToLower(busID)
	for i, line := range strings.Split(out, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 2 {
			continue
		}
		busPart := strings.ToLower(strings.TrimSpace(parts[1]))
		// rocm-smi may include the PCI domain ("0000:01:00.0"); lspci omits it ("01:00.0").
		if busPart != busLow && !strings.HasSuffix(busPart, ":"+busLow) {
			continue
		}
		// Extract the first digit sequence from the device field (handles "GPU[0]", "card0", "0").
		devField := strings.TrimSpace(parts[0])
		start := -1
		for j, ch := range devField {
			if ch >= '0' && ch <= '9' {
				if start == -1 {
					start = j
				}
			} else if start != -1 {
				if n, err := strconv.Atoi(devField[start:j]); err == nil {
					return n
				}
				start = -1
			}
		}
		if start != -1 {
			if n, err := strconv.Atoi(devField[start:]); err == nil {
				return n
			}
		}
	}
	return -1
}

func getGPUs() []shared.GPU {
	var gpus []shared.GPU

	lspciOutput, err := shared.RunCommand("lspci", "-nn")
	if err != nil {
		return gpus
	}

	for _, line := range strings.Split(lspciOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "vga") &&
			!strings.Contains(lower, "3d controller") &&
			!strings.Contains(lower, "display controller") {
			continue
		}
		g := shared.GPU{
			Name:          "Unknown",
			Manufacturer:  "Unknown",
			Architecture:  "Unknown",
			Chipset:       "Unknown",
			DedicatedVRAM: "Unknown",
			SharedVRAM:    "Unknown",
			DriverVersion: "Unknown",
			DriverDate:    "Unknown",
			HardwareID:    "Unknown",
			CurrentStatus: "Unknown",
		}
		// lspci -nn format: "01:00.0 VGA compatible controller [0300]: NVIDIA GeForce RTX 3080 [10de:2206] (rev a1)"
		busID := strings.Fields(line)[0]
		if parts := strings.SplitN(line, ": ", 2); len(parts) == 2 {
			desc := parts[1]
			// Extract [vendor:device] hardware ID — it's the last bracket pair.
			if lb := strings.LastIndex(desc, "["); lb >= 0 {
				if rb := strings.Index(desc[lb:], "]"); rb > 0 {
					g.HardwareID = desc[lb+1 : lb+rb]
					desc = strings.TrimSpace(desc[:lb])
				}
			}
			// Strip trailing "(rev XX)".
			if i := strings.Index(desc, " (rev "); i > 0 {
				desc = strings.TrimSpace(desc[:i])
			}
			g.Name = desc
			g.Chipset = desc
			g.Manufacturer = linuxGPUManufacturer(desc)
		}

		// VRAM from lspci -v: use the largest prefetchable BAR, which is the VRAM region
		// on discrete GPUs. Kernel driver name drives CurrentStatus and DriverVersion lookup.
		var kernelDriver string
		if vOut, vErr := shared.RunCommand("lspci", "-v", "-s", busID); vErr == nil {
			var maxVRAMBytes int64
			for _, vLine := range strings.Split(vOut, "\n") {
				vLine = strings.TrimSpace(vLine)
				if strings.Contains(vLine, "prefetchable") && strings.Contains(vLine, "[size=") {
					if i := strings.LastIndex(vLine, "[size="); i >= 0 {
						if j := strings.Index(vLine[i:], "]"); j > 0 {
							sizeStr := vLine[i+6 : i+j]
							if sz := parsePCISize(sizeStr); sz > maxVRAMBytes {
								maxVRAMBytes = sz
								g.DedicatedVRAM = sizeStr
							}
						}
					}
				}
				if strings.HasPrefix(vLine, "Kernel driver in use:") {
					kernelDriver = strings.TrimSpace(strings.TrimPrefix(vLine, "Kernel driver in use:"))
					g.CurrentStatus = "OK"
				}
			}
		}

		// Attempt to read the real driver version from sysfs. Built-in kernel modules
		// (i915, amdgpu) typically don't expose this file; NVIDIA's out-of-tree driver does.
		if kernelDriver != "" {
			versionPath := fmt.Sprintf("/sys/module/%s/version", kernelDriver)
			if vStr, vErr := shared.ReadFileContent(versionPath); vErr == nil {
				if ver := strings.TrimSpace(vStr); ver != "" {
					g.DriverVersion = ver
				}
			}
		}

		switch g.Manufacturer {
		case "NVIDIA":
			// nvidia-smi provides accurate per-GPU name, VRAM (MiB), and driver version.
			// --id accepts the PCI bus ID in 0000:BB:DD.F format.
			nOut, nErr := shared.RunCommand("nvidia-smi",
				"--query-gpu=name,memory.total,driver_version",
				"--format=csv,noheader,nounits",
				"--id=0000:"+busID)
			if nErr == nil {
				firstLine := strings.TrimSpace(strings.SplitN(nOut, "\n", 2)[0])
				fields := strings.SplitN(firstLine, ", ", 3)
				if len(fields) >= 1 && fields[0] != "" {
					g.Name = fields[0]
					g.Chipset = fields[0]
				}
				if len(fields) >= 2 && fields[1] != "" {
					g.DedicatedVRAM = fields[1] + " MiB"
				}
				if len(fields) >= 3 && fields[2] != "" {
					g.DriverVersion = fields[2]
				}
			}
		case "AMD":
			// Try the DRM sysfs path first — the amdgpu driver exposes this without any
			// extra tooling. Fall back to rocm-smi for HPC/workstation setups.
			if vramBytes := linuxSysfsVRAMBytes(busID); vramBytes > 0 {
				g.DedicatedVRAM = formatLinuxVRAM(vramBytes)
			} else {
				deviceIdx := findROCmDeviceIndex(busID)
				if deviceIdx >= 0 {
					amdOut, amdErr := shared.RunCommand("rocm-smi", "-d", strconv.Itoa(deviceIdx), "--showmeminfo", "vram", "--csv")
					if amdErr == nil {
						for i, amdLine := range strings.Split(amdOut, "\n") {
							amdLine = strings.TrimSpace(amdLine)
							if i == 0 || amdLine == "" {
								continue
							}
							amdParts := strings.Split(amdLine, ",")
							if len(amdParts) < 2 {
								continue
							}
							vramStr := strings.TrimSpace(amdParts[len(amdParts)-1])
							if vramBytes, err := strconv.ParseInt(vramStr, 10, 64); err == nil && vramBytes > 0 {
								g.DedicatedVRAM = formatLinuxVRAM(vramBytes)
							}
							break
						}
					}
				}
			}
		case "Intel":
			// Read PCI_ID directly from the device's uevent via its bus ID, avoiding the
			// DRM card iteration that could overwrite HardwareID with a different GPU's data.
			ueventPath := fmt.Sprintf("/sys/bus/pci/devices/0000:%s/uevent", busID)
			if data, err := shared.ReadFileContent(ueventPath); err == nil {
				for _, l := range strings.Split(data, "\n") {
					if strings.HasPrefix(l, "PCI_ID=") {
						g.HardwareID = strings.TrimPrefix(l, "PCI_ID=")
						break
					}
				}
			}
		}

		// Architecture is determined after VRAM collection:
		// - NVIDIA has no integrated desktop/server GPU variants.
		// - Intel GPUs are integrated unless the name indicates Arc (discrete).
		// - AMD with detected VRAM is discrete; without, it is an integrated APU.
		g.Architecture = linuxGPUArchitecture(g.Manufacturer, g.Name, g.DedicatedVRAM != "Unknown")

		if g.Name != "Unknown" {
			gpus = append(gpus, g)
		}
	}
	return gpus
}
