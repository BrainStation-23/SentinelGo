package gpu

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// macGPUVendorFromStr parses a system_profiler spdisplays_vendor string such as
// "Intel (0x8086)" or "Apple (0x106b)" into a canonical manufacturer and an initial
// architecture guess. The architecture may be refined later by the VRAM key presence.
func macGPUVendorFromStr(vendorStr string) (manufacturer, architecture string) {
	// Strip the parenthesised PCI vendor ID suffix, if present.
	base := vendorStr
	if idx := strings.Index(vendorStr, " ("); idx > 0 {
		base = strings.TrimSpace(vendorStr[:idx])
	}
	baseLow := strings.ToLower(base)
	switch {
	case strings.Contains(baseLow, "apple"):
		return "Apple", "Integrated"
	case strings.Contains(baseLow, "intel"):
		return "Intel", "Integrated"
	case strings.Contains(baseLow, "amd") ||
		strings.HasPrefix(baseLow, "ati") ||
		strings.Contains(baseLow, "advanced micro"):
		return "AMD", "Discrete"
	case strings.Contains(baseLow, "nvidia"):
		return "NVIDIA", "Discrete"
	}
	if base == "" {
		return "Unknown", "Unknown"
	}
	return base, "Unknown"
}

// newUnknownDarwinGPU returns a GPU pre-populated with the same "Unknown"
// placeholders used before any system_profiler fields are applied.
func newUnknownDarwinGPU() shared.GPU {
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
		CurrentStatus: "unknown",
	}
}

// applyDarwinVRAM sets dedicated/shared VRAM (and refines Architecture) from
// the spdisplays_vram_shared and spdisplays_vram keys of a display entry.
func applyDarwinVRAM(g *shared.GPU, dm map[string]any) {
	// Presence of spdisplays_vram_shared key means GPU uses shared system memory.
	// Its value is the shared VRAM size (e.g. "1536 MB"), not a yes/no flag.
	if _, hasSharedKey := dm["spdisplays_vram_shared"]; hasSharedKey {
		g.Architecture = "Integrated"
		if v, ok := dm["spdisplays_vram_shared"].(string); ok {
			g.SharedVRAM = v
		}
	}
	// spdisplays_vram is dedicated VRAM for discrete GPUs, or total GPU memory for integrated.
	v, ok := dm["spdisplays_vram"].(string)
	if !ok {
		return
	}
	if g.Architecture == "Integrated" {
		if g.SharedVRAM == "Unknown" {
			g.SharedVRAM = v
		}
		return
	}
	g.DedicatedVRAM = v
	if g.Architecture == "Unknown" {
		g.Architecture = "Discrete"
	}
}

// applyDarwinHardwareID sets HardwareID from the vendor/device ID keys.
// system_profiler does not expose GPU driver versions — they are bundled with
// the OS as kernel extensions and not surfaced through SPDisplaysDataType.
// Apple Silicon GPUs have no PCI vendor/device IDs; HardwareID remains "Unknown".
func applyDarwinHardwareID(g *shared.GPU, dm map[string]any) {
	vendorID, _ := dm["spdisplays_vendor_id"].(string)
	deviceID, _ := dm["spdisplays_device_id"].(string)
	switch {
	case vendorID != "" && deviceID != "":
		g.HardwareID = vendorID + ":" + deviceID
	case vendorID != "":
		g.HardwareID = vendorID
	}
}

// parseDarwinDisplay converts one SPDisplaysDataType entry into a GPU. ok is
// false when d isn't a display map, or the parsed GPU has no name.
func parseDarwinDisplay(d any) (g shared.GPU, ok bool) {
	dm, ok := d.(map[string]any)
	if !ok {
		return shared.GPU{}, false
	}
	g = newUnknownDarwinGPU()
	if v, ok := dm["_name"].(string); ok {
		g.Name = v
		g.Chipset = v
	}
	if v, ok := dm["spdisplays_vendor"].(string); ok {
		g.Manufacturer, g.Architecture = macGPUVendorFromStr(v)
	}
	applyDarwinVRAM(&g, dm)
	applyDarwinHardwareID(&g, dm)
	return g, g.Name != "Unknown"
}

func getGPUs() []shared.GPU {
	var gpus []shared.GPU

	output, err := shared.RunCommand("system_profiler", "SPDisplaysDataType", "-json")
	if err != nil {
		return gpus
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return gpus
	}
	displaysRaw, ok := result["SPDisplaysDataType"]
	if !ok {
		return gpus
	}
	displays, ok := displaysRaw.([]any)
	if !ok {
		return gpus
	}

	for _, d := range displays {
		if g, ok := parseDarwinDisplay(d); ok {
			gpus = append(gpus, g)
		}
	}
	return gpus
}
