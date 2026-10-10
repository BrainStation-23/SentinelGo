package gpu

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Test seams: production always runs the real commands against the real
// sysfs mount; tests swap these for fixture output and a t.TempDir() tree.
var (
	gpuRunCommand = shared.RunCommand
	gpuSysfsRoot  = "/sys"
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
	// Reject negative sizes and values whose n*mul would overflow int64.
	if err != nil || n < 0 || n > math.MaxInt64/mul {
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
	drmBase := gpuSysfsRoot + "/class/drm"
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

// rocmBusMatches reports whether a "--showbus --csv" line's bus column (the
// second CSV field) matches busLow, and if so returns the device field (the
// first CSV field, e.g. "GPU[0]", "card0", "0").
func rocmBusMatches(line, busLow string) (devField string, ok bool) {
	parts := strings.SplitN(line, ",", 2)
	if len(parts) < 2 {
		return "", false
	}
	busPart := strings.ToLower(strings.TrimSpace(parts[1]))
	// rocm-smi may include the PCI domain ("0000:01:00.0"); lspci omits it ("01:00.0").
	if busPart != busLow && !strings.HasSuffix(busPart, ":"+busLow) {
		return "", false
	}
	return strings.TrimSpace(parts[0]), true
}

// firstIntInString extracts the first contiguous run of digits in s and
// parses it as an int (handles device fields like "GPU[0]", "card0", "0").
func firstIntInString(s string) (int, bool) {
	start := -1
	for i, ch := range s {
		if ch >= '0' && ch <= '9' {
			if start == -1 {
				start = i
			}
			continue
		}
		if start == -1 {
			continue
		}
		if n, err := strconv.Atoi(s[start:i]); err == nil {
			return n, true
		}
		start = -1
	}
	if start == -1 {
		return 0, false
	}
	n, err := strconv.Atoi(s[start:])
	return n, err == nil
}

// findROCmDeviceIndex maps a PCI bus ID (e.g. "01:00.0") to a rocm-smi device
// index so VRAM can be queried per-GPU rather than from a global dump.
func findROCmDeviceIndex(busID string) int {
	out, err := gpuRunCommand("rocm-smi", "--showbus", "--csv")
	if err != nil {
		return -1
	}
	busLow := strings.ToLower(busID)
	for i, line := range strings.Split(out, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		devField, ok := rocmBusMatches(line, busLow)
		if !ok {
			continue
		}
		if n, ok := firstIntInString(devField); ok {
			return n
		}
	}
	return -1
}

// newUnknownLinuxGPU returns a GPU pre-populated with the same "Unknown"
// placeholders used before any lspci fields are applied.
func newUnknownLinuxGPU() shared.GPU {
	return shared.GPU{
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
}

// isLinuxGPULine reports whether an lspci -nn line describes a graphics
// device (a VGA, 3D, or generic display controller).
func isLinuxGPULine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "vga") ||
		strings.Contains(lower, "3d controller") ||
		strings.Contains(lower, "display controller")
}

// extractLspciHardwareID pulls the last bracketed [vendor:device] pair out of
// an lspci description, returning the description with that suffix removed.
func extractLspciHardwareID(desc string) (hwID, rest string, ok bool) {
	lb := strings.LastIndex(desc, "[")
	if lb < 0 {
		return "", desc, false
	}
	rb := strings.Index(desc[lb:], "]")
	if rb <= 0 {
		return "", desc, false
	}
	return desc[lb+1 : lb+rb], strings.TrimSpace(desc[:lb]), true
}

// stripLspciRevSuffix removes a trailing "(rev XX)" from an lspci description.
func stripLspciRevSuffix(desc string) string {
	if i := strings.Index(desc, " (rev "); i > 0 {
		return strings.TrimSpace(desc[:i])
	}
	return desc
}

// parseLspciLine parses a single lspci -nn line (already confirmed to
// describe a GPU) into its PCI bus ID and a GPU populated with Name,
// Chipset, Manufacturer, and HardwareID.
// lspci -nn format: "01:00.0 VGA compatible controller [0300]: NVIDIA GeForce RTX 3080 [10de:2206] (rev a1)"
func parseLspciLine(line string) (busID string, g shared.GPU) {
	g = newUnknownLinuxGPU()
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", g
	}
	busID = fields[0]
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) != 2 {
		return busID, g
	}
	desc := parts[1]
	if hwID, rest, ok := extractLspciHardwareID(desc); ok {
		g.HardwareID = hwID
		desc = rest
	}
	desc = stripLspciRevSuffix(desc)
	g.Name = desc
	g.Chipset = desc
	g.Manufacturer = linuxGPUManufacturer(desc)
	return busID, g
}

// extractPrefetchableSize returns the "[size=XXX]" value from an lspci -v
// line describing a prefetchable BAR, which is the VRAM region on discrete GPUs.
func extractPrefetchableSize(vLine string) (string, bool) {
	if !strings.Contains(vLine, "prefetchable") || !strings.Contains(vLine, "[size=") {
		return "", false
	}
	i := strings.LastIndex(vLine, "[size=")
	if i < 0 {
		return "", false
	}
	j := strings.Index(vLine[i:], "]")
	if j <= 0 {
		return "", false
	}
	return vLine[i+6 : i+j], true
}

// extractKernelDriver returns the driver name from an lspci -v
// "Kernel driver in use:" line.
func extractKernelDriver(vLine string) (string, bool) {
	if !strings.HasPrefix(vLine, "Kernel driver in use:") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(vLine, "Kernel driver in use:")), true
}

// queryLinuxPCIDetails runs lspci -v for busID and extracts the largest
// prefetchable BAR size (VRAM on discrete GPUs) and the in-use kernel driver
// name, which drives CurrentStatus and the DriverVersion sysfs lookup.
func queryLinuxPCIDetails(busID string) (dedicatedVRAM, currentStatus, kernelDriver string) {
	dedicatedVRAM = "Unknown"
	currentStatus = "Unknown"
	vOut, vErr := gpuRunCommand("lspci", "-v", "-s", busID)
	if vErr != nil {
		return dedicatedVRAM, currentStatus, kernelDriver
	}
	var maxVRAMBytes int64
	for _, vLine := range strings.Split(vOut, "\n") {
		vLine = strings.TrimSpace(vLine)
		if sizeStr, ok := extractPrefetchableSize(vLine); ok {
			if sz := parsePCISize(sizeStr); sz > maxVRAMBytes {
				maxVRAMBytes = sz
				dedicatedVRAM = sizeStr
			}
		}
		if driver, ok := extractKernelDriver(vLine); ok {
			kernelDriver = driver
			currentStatus = "OK"
		}
	}
	return dedicatedVRAM, currentStatus, kernelDriver
}

// linuxDriverVersionFromSysfs reads the real driver version from
// /sys/module/<driver>/version. Built-in kernel modules (i915, amdgpu)
// typically don't expose this file; NVIDIA's out-of-tree driver does.
// Returns "" when kernelDriver is empty or the file can't be read.
func linuxDriverVersionFromSysfs(kernelDriver string) string {
	if kernelDriver == "" {
		return ""
	}
	versionPath := fmt.Sprintf("%s/module/%s/version", gpuSysfsRoot, kernelDriver)
	vStr, vErr := shared.ReadFileContent(versionPath)
	if vErr != nil {
		return ""
	}
	return strings.TrimSpace(vStr)
}

// enrichNvidiaGPU refines Name/Chipset, DedicatedVRAM, and DriverVersion
// using nvidia-smi, which provides more accurate per-GPU data than lspci.
// --id accepts the PCI bus ID in 0000:BB:DD.F format.
func enrichNvidiaGPU(g *shared.GPU, busID string) {
	nOut, nErr := gpuRunCommand("nvidia-smi",
		"--query-gpu=name,memory.total,driver_version",
		"--format=csv,noheader,nounits",
		"--id=0000:"+busID)
	if nErr != nil {
		return
	}
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

// amdVRAMFromROCm queries rocm-smi for the VRAM size of the device at busID,
// used as a fallback when the DRM sysfs path doesn't expose VRAM. Only the
// first data line of the CSV output is considered.
func amdVRAMFromROCm(busID string) (string, bool) {
	deviceIdx := findROCmDeviceIndex(busID)
	if deviceIdx < 0 {
		return "", false
	}
	amdOut, amdErr := gpuRunCommand("rocm-smi", "-d", strconv.Itoa(deviceIdx), "--showmeminfo", "vram", "--csv")
	if amdErr != nil {
		return "", false
	}
	totalCol := 1
	for i, amdLine := range strings.Split(amdOut, "\n") {
		amdLine = strings.TrimSpace(amdLine)
		if i == 0 {
			totalCol = rocmTotalVRAMColumn(amdLine)
			continue
		}
		if amdLine == "" {
			continue
		}
		amdParts := strings.Split(amdLine, ",")
		if len(amdParts) <= totalCol {
			continue
		}
		vramStr := strings.TrimSpace(amdParts[totalCol])
		vramBytes, err := strconv.ParseInt(vramStr, 10, 64)
		if err == nil && vramBytes > 0 {
			return formatLinuxVRAM(vramBytes), true
		}
		return "", false
	}
	return "", false
}

// rocmTotalVRAMColumn returns the index of the "VRAM Total Memory" column in
// a rocm-smi --showmeminfo CSV header. Newer rocm-smi versions also print a
// "VRAM Total Used Memory" column, so the column is located by name; the first
// value column is assumed when the header doesn't name it.
func rocmTotalVRAMColumn(header string) int {
	for i, col := range strings.Split(header, ",") {
		col = strings.ToLower(col)
		if strings.Contains(col, "total memory") && !strings.Contains(col, "used") {
			return i
		}
	}
	return 1
}

// enrichAMDGPU sets DedicatedVRAM for an AMD GPU. It tries the DRM sysfs
// path first — the amdgpu driver exposes this without any extra tooling —
// and falls back to rocm-smi for HPC/workstation setups.
func enrichAMDGPU(g *shared.GPU, busID string) {
	if vramBytes := linuxSysfsVRAMBytes(busID); vramBytes > 0 {
		g.DedicatedVRAM = formatLinuxVRAM(vramBytes)
		return
	}
	if vramStr, ok := amdVRAMFromROCm(busID); ok {
		g.DedicatedVRAM = vramStr
	}
}

// enrichIntelGPU sets HardwareID by reading PCI_ID directly from the
// device's uevent via its bus ID, avoiding the DRM card iteration that could
// overwrite HardwareID with a different GPU's data.
func enrichIntelGPU(g *shared.GPU, busID string) {
	ueventPath := fmt.Sprintf("%s/bus/pci/devices/0000:%s/uevent", gpuSysfsRoot, busID)
	data, err := shared.ReadFileContent(ueventPath)
	if err != nil {
		return
	}
	for _, l := range strings.Split(data, "\n") {
		if strings.HasPrefix(l, "PCI_ID=") {
			g.HardwareID = strings.TrimPrefix(l, "PCI_ID=")
			return
		}
	}
}

// enrichLinuxGPUByVendor dispatches to the vendor-specific enrichment step
// that refines a GPU's fields beyond what lspci alone provides.
func enrichLinuxGPUByVendor(g *shared.GPU, busID string) {
	switch g.Manufacturer {
	case "NVIDIA":
		enrichNvidiaGPU(g, busID)
	case "AMD":
		enrichAMDGPU(g, busID)
	case "Intel":
		enrichIntelGPU(g, busID)
	}
}

// buildLinuxGPU parses one lspci -nn line into a fully enriched GPU. ok is
// false when the line doesn't describe a graphics device or the parsed GPU
// has no name.
func buildLinuxGPU(line string) (shared.GPU, bool) {
	if !isLinuxGPULine(line) {
		return shared.GPU{}, false
	}
	busID, g := parseLspciLine(line)

	var kernelDriver string
	g.DedicatedVRAM, g.CurrentStatus, kernelDriver = queryLinuxPCIDetails(busID)
	if ver := linuxDriverVersionFromSysfs(kernelDriver); ver != "" {
		g.DriverVersion = ver
	}

	enrichLinuxGPUByVendor(&g, busID)

	// Architecture is determined after VRAM collection:
	// - NVIDIA has no integrated desktop/server GPU variants.
	// - Intel GPUs are integrated unless the name indicates Arc (discrete).
	// - AMD with detected VRAM is discrete; without, it is an integrated APU.
	g.Architecture = linuxGPUArchitecture(g.Manufacturer, g.Name, g.DedicatedVRAM != "Unknown")
	return g, g.Name != "Unknown"
}

func getGPUs() []shared.GPU {
	var gpus []shared.GPU

	lspciOutput, err := gpuRunCommand("lspci", "-nn")
	if err != nil {
		return gpus
	}

	for _, line := range strings.Split(lspciOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if g, ok := buildLinuxGPU(line); ok {
			gpus = append(gpus, g)
		}
	}
	return gpus
}
