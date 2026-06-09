package display

import (
	"encoding/json"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getDisplays() []shared.Display {
	var displays []shared.Display

	output, err := shared.RunCommand("system_profiler", "SPDisplaysDataType", "-json")
	if err != nil {
		return displays
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return displays
	}
	displaysRaw, ok := result["SPDisplaysDataType"]
	if !ok {
		return displays
	}
	displaysArr, ok := displaysRaw.([]any)
	if !ok {
		return displays
	}

	for _, entry := range displaysArr {
		gm, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		// GPU-level vendor used as fallback manufacturer for displays that don't
		// carry their own vendor field (e.g. Apple built-in panels).
		gpuVendorRaw, _ := gm["spdisplays_vendor"].(string)
		gpuVendor := cleanMacVendorName(gpuVendorRaw)

		items, hasItems := gm["_items"].([]any)
		if !hasItems {
			// Legacy format: entry itself is the display when it has resolution data.
			if _, hasRes := gm["spdisplays_resolution"]; hasRes {
				if d, ok := buildMacDisplay(gm, gpuVendor); ok {
					displays = append(displays, d)
				}
			}
			continue
		}
		for _, item := range items {
			dm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if d, ok := buildMacDisplay(dm, gpuVendor); ok {
				displays = append(displays, d)
			}
		}
	}
	return displays
}

func buildMacDisplay(dm map[string]any, gpuVendor string) (shared.Display, bool) {
	name, _ := dm["_name"].(string)
	if name == "" {
		return shared.Display{}, false
	}
	d := shared.Display{
		Description:  name,
		Manufacturer: "Unknown",
		SerialNumber: "Unknown",
		Model:        name,
	}

	if v, ok := dm["spdisplays_vendor"].(string); ok && v != "" {
		d.Manufacturer = cleanMacVendorName(v)
	} else if gpuVendor != "" {
		d.Manufacturer = gpuVendor
	}

	if v, ok := dm["spdisplays_serial_number"].(string); ok && v != "" {
		d.SerialNumber = v
	}

	if v, ok := dm["spdisplays_inches"].(string); ok && v != "" {
		if sz, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && sz > 0 {
			d.Size = sz
		}
	}
	if d.Size == 0 {
		if size := shared.ParseDisplaySizeFromName(name); size > 0 {
			d.Size = size
		}
	}

	if v, ok := dm["spdisplays_resolution"].(string); ok && v != "" {
		res, hz := parseResolutionAndRefreshRate(v)
		d.Resolution = res
		d.RefreshRate = hz
	}

	if v, ok := dm["spdisplays_connection_type"].(string); ok && v != "" {
		d.ConnectionType = macDisplayConnectionType(v)
	}

	return d, true
}

// cleanMacVendorName strips the PCI-ID suffix from strings like "Apple (0x106b)"
// and returns the bare vendor name. Returns the input unchanged if no " (" is found.
func cleanMacVendorName(s string) string {
	if idx := strings.Index(s, " ("); idx > 0 {
		name := strings.TrimSpace(s[:idx])
		if strings.EqualFold(name, "unknown") {
			return ""
		}
		return name
	}
	return s
}

// parseResolutionAndRefreshRate parses strings like "2560 x 1440 @ 60.00Hz" or
// "3456 x 2160 Retina" into a compact "WxH" resolution and Hz value.
func parseResolutionAndRefreshRate(s string) (resolution string, refreshRate float64) {
	parts := strings.Fields(s)
	for i := 1; i+1 < len(parts); i++ {
		if strings.ToLower(parts[i]) == "x" {
			w, h := parts[i-1], parts[i+1]
			if _, err := strconv.Atoi(w); err == nil {
				if _, err := strconv.Atoi(h); err == nil {
					resolution = w + "x" + h
				}
			}
		}
	}
	for _, part := range parts {
		p := strings.TrimPrefix(part, "@")
		if strings.HasSuffix(p, "Hz") {
			if rate, err := strconv.ParseFloat(strings.TrimSuffix(p, "Hz"), 64); err == nil {
				refreshRate = rate
			}
		}
	}
	return resolution, refreshRate
}

// macDisplayConnectionType converts system_profiler connection type tokens
// (e.g. "spdisplays_internal", "spdisplays_displayport") to human-readable strings.
func macDisplayConnectionType(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "internal"):
		return "Internal"
	case strings.Contains(s, "displayport"):
		return "DisplayPort"
	case strings.Contains(s, "thunderbolt"):
		return "Thunderbolt"
	case strings.Contains(s, "hdmi"):
		return "HDMI"
	case strings.Contains(s, "vga"):
		return "VGA"
	case strings.Contains(s, "dvi"):
		return "DVI"
	case strings.Contains(s, "usb"):
		return "USB"
	}
	return ""
}
