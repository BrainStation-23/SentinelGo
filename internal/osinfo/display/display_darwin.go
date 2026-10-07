package display

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
		displays = append(displays, displaysFromGPUEntry(gm)...)
	}
	return displays
}

// displaysFromGPUEntry extracts the displays attached to a single GPU entry
// from system_profiler's SPDisplaysDataType output.
func displaysFromGPUEntry(gm map[string]any) []shared.Display {
	// GPU-level vendor used as fallback manufacturer for displays that don't
	// carry their own vendor field (e.g. Apple built-in panels).
	gpuVendorRaw, _ := gm["spdisplays_vendor"].(string)
	gpuVendor := cleanMacVendorName(gpuVendorRaw)

	// macOS 13+: display items are nested under "spdisplays_ndrvs".
	// Older format used "_items".
	items, hasItems := gm["spdisplays_ndrvs"].([]any)
	if !hasItems {
		items, hasItems = gm["_items"].([]any)
	}
	if hasItems {
		return buildMacDisplaysFromItems(items, gpuVendor)
	}

	// Legacy format: entry itself is the display when it has resolution data.
	_, hasNewRes := gm["_spdisplays_resolution"]
	_, hasOldRes := gm["spdisplays_resolution"]
	if hasNewRes || hasOldRes {
		if d, ok := buildMacDisplay(gm, gpuVendor); ok {
			return []shared.Display{d}
		}
	}
	return nil
}

// buildMacDisplaysFromItems converts each nested display item (the modern
// "spdisplays_ndrvs"/"_items" list) into a shared.Display.
func buildMacDisplaysFromItems(items []any, gpuVendor string) []shared.Display {
	var displays []shared.Display
	for _, item := range items {
		dm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if d, ok := buildMacDisplay(dm, gpuVendor); ok {
			displays = append(displays, d)
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

	if m := macDisplayManufacturer(dm, gpuVendor); m != "" {
		d.Manufacturer = m
	}
	if s := macDisplaySerialNumber(dm); s != "" {
		d.SerialNumber = s
	}
	d.Size = macDisplaySize(dm, name)
	d.Resolution, d.RefreshRate = macDisplayResolutionAndRefresh(dm)

	if v, ok := dm["spdisplays_connection_type"].(string); ok && v != "" {
		d.ConnectionType = macDisplayConnectionType(v)
	}

	// Year: present for external displays; 0 for built-in panels (skip those)
	d.Year = macDisplayYear(dm)

	// Monitor type tags derived from spdisplays_display_type
	if v, ok := dm["spdisplays_display_type"].(string); ok && v != "" {
		d.MonitorType = parseMacDisplayType(v)
	}

	return d, true
}

// macDisplayManufacturer resolves a display's manufacturer from its own
// vendor field, falling back to the GPU-level vendor. Returns "" if neither
// is available (caller keeps its existing default in that case).
func macDisplayManufacturer(dm map[string]any, gpuVendor string) string {
	if v, ok := dm["spdisplays_vendor"].(string); ok && v != "" {
		return cleanMacVendorName(v)
	}
	return gpuVendor
}

// macDisplaySerialNumber reads the serial number, preferring the modern key
// "_spdisplays_display-serial-number" over the legacy "spdisplays_serial_number".
func macDisplaySerialNumber(dm map[string]any) string {
	if v, ok := dm["_spdisplays_display-serial-number"].(string); ok && v != "" {
		return v
	}
	if v, ok := dm["spdisplays_serial_number"].(string); ok && v != "" {
		return v
	}
	return ""
}

// macDisplaySize returns the physical size in inches from "spdisplays_inches",
// falling back to parsing it out of the display name.
func macDisplaySize(dm map[string]any, name string) float64 {
	if v, ok := dm["spdisplays_inches"].(string); ok && v != "" {
		if sz, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && sz > 0 {
			return sz
		}
	}
	return shared.ParseDisplaySizeFromName(name)
}

// macDisplayResolutionAndRefresh derives the resolution and refresh rate from
// the native pixel count ("_spdisplays_pixels") and the resolution/refresh
// string ("_spdisplays_resolution" or the legacy "spdisplays_resolution").
func macDisplayResolutionAndRefresh(dm map[string]any) (resolution string, refreshRate float64) {
	// Native (physical) pixel resolution, e.g. "_spdisplays_pixels": "3024 x 1964"
	if v, ok := dm["_spdisplays_pixels"].(string); ok && v != "" {
		if res, _ := parseResolutionAndRefreshRate(v); res != "" {
			resolution = res
		}
	}

	// Refresh rate from "_spdisplays_resolution"; also provides logical resolution
	// as a fallback when native pixels were not available.
	if v, ok := dm["_spdisplays_resolution"].(string); ok && v != "" {
		logicalRes, hz := parseResolutionAndRefreshRate(v)
		refreshRate = hz
		if resolution == "" {
			resolution = logicalRes
		}
	} else if v, ok := dm["spdisplays_resolution"].(string); ok && v != "" {
		res, hz := parseResolutionAndRefreshRate(v)
		if resolution == "" {
			resolution = res
		}
		refreshRate = hz
	}
	return resolution, refreshRate
}

// macDisplayYear returns the manufacture year from "_spdisplays_display-year",
// present for external displays; built-in panels report 0.
func macDisplayYear(dm map[string]any) int {
	if v, ok := dm["_spdisplays_display-year"].(string); ok && v != "" {
		if yr, err := strconv.Atoi(v); err == nil && yr > 1990 {
			return yr
		}
	}
	return 0
}

// cleanMacVendorName normalises vendor strings from system_profiler:
//   - "sppci_vendor_Apple"  → "Apple"
//   - "Apple (0x106b)"      → "Apple"
func cleanMacVendorName(s string) string {
	if strings.HasPrefix(s, "sppci_vendor_") {
		return s[len("sppci_vendor_"):]
	}
	if idx := strings.Index(s, " ("); idx > 0 {
		name := strings.TrimSpace(s[:idx])
		if strings.EqualFold(name, "unknown") {
			return ""
		}
		return name
	}
	return s
}

// parseMacDisplayType converts a spdisplays_display_type token like
// "spdisplays_built-in-liquid-retina-xdr" into human-readable tags.
func parseMacDisplayType(s string) []string {
	s = strings.TrimPrefix(strings.ToLower(s), "spdisplays_")
	if s == "" {
		return nil
	}
	var tags []string
	if strings.Contains(s, "built-in") {
		tags = append(tags, "Built-In")
	} else if strings.Contains(s, "external") {
		tags = append(tags, "External")
	}
	switch {
	case strings.Contains(s, "liquid-retina-xdr"):
		tags = append(tags, "Liquid Retina XDR")
	case strings.Contains(s, "retina-xdr"):
		tags = append(tags, "Retina XDR")
	case strings.Contains(s, "retina"):
		tags = append(tags, "Retina")
	}
	if len(tags) == 0 {
		parts := strings.Split(s, "-")
		var words []string
		for _, p := range parts {
			if p != "" {
				// Capitalise the first rune, not the first byte, so a
				// multi-byte character isn't split into invalid UTF-8.
				r, size := utf8.DecodeRuneInString(p)
				words = append(words, string(unicode.ToUpper(r))+p[size:])
			}
		}
		return []string{strings.Join(words, " ")}
	}
	return tags
}

// parseResolutionAndRefreshRate parses strings like "2560 x 1440 @ 60.00Hz" or
// "3456 x 2160 Retina" into a compact "WxH" resolution and Hz value.
func parseResolutionAndRefreshRate(s string) (resolution string, refreshRate float64) {
	parts := strings.Fields(s)
	for i := 1; i+1 < len(parts); i++ {
		if strings.ToLower(parts[i]) == "x" {
			w, h := parts[i-1], parts[i+1]
			if isPositiveDecimal(w) && isPositiveDecimal(h) {
				resolution = w + "x" + h
			}
		}
	}
	for _, part := range parts {
		p := strings.TrimPrefix(part, "@")
		if strings.HasSuffix(p, "Hz") {
			// ParseFloat accepts "NaN" and "Inf", which encoding/json cannot
			// marshal and would fail the whole heartbeat payload.
			rate, err := strconv.ParseFloat(strings.TrimSuffix(p, "Hz"), 64)
			if err == nil && rate > 0 && !math.IsInf(rate, 0) {
				refreshRate = rate
			}
		}
	}
	return resolution, refreshRate
}

// isPositiveDecimal reports whether s is a plain base-10 integer greater than
// zero (no sign, no spaces), as used for pixel dimensions.
func isPositiveDecimal(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && s[0] != '+'
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
