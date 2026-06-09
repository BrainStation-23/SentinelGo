package display

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getDisplays() []shared.Display {
	var displays []shared.Display

	connectedDisplays := make(map[string]bool)
	displayRefreshRates := make(map[string]float64)
	displayResolutions := make(map[string]string)
	if output, err := shared.RunCommand("xrandr", "--query"); err == nil {
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, " connected") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					connectedDisplays[parts[0]] = true
					for _, part := range parts[1:] {
						// Geometry token: "NxM+X+Y" — current active mode
						if plusIdx := strings.Index(part, "+"); plusIdx > 0 {
							if res := part[:plusIdx]; strings.Contains(res, "x") {
								halves := strings.SplitN(res, "x", 2)
								if len(halves) == 2 {
									if _, e1 := strconv.Atoi(halves[0]); e1 == nil {
										if _, e2 := strconv.Atoi(halves[1]); e2 == nil {
											displayResolutions[parts[0]] = res
										}
									}
								}
							}
							break
						}
						// Refresh rate on mode lines (indented) — won't appear here,
						// but kept for compatibility with non-standard xrandr output
						if strings.Contains(part, "*") || strings.Contains(part, "+") {
							rateStr := strings.TrimSuffix(strings.TrimSuffix(part, "*"), "+")
							if refreshRate, err := strconv.ParseFloat(rateStr, 64); err == nil {
								displayRefreshRates[parts[0]] = refreshRate
							}
						}
					}
				}
			}
		}
	}

	drmDirs, err := os.ReadDir("/sys/class/drm")
	if err != nil {
		return displays
	}
	for _, dir := range drmDirs {
		name := dir.Name()
		if strings.HasPrefix(name, "card") && !strings.Contains(name, "-") {
			continue
		}
		if !strings.Contains(name, "DP-") && !strings.Contains(name, "HDMI-") &&
			!strings.Contains(name, "VGA-") && !strings.Contains(name, "eDP-") &&
			!strings.HasSuffix(name, "-") {
			continue
		}

		connectorName := name
		if idx := strings.Index(name, "-"); idx >= 0 {
			connectorName = name[idx+1:]
		}

		edidPath := fmt.Sprintf("/sys/class/drm/%s/edid", name)
		edidData, edidErr := shared.ReadFileBytes(edidPath)
		isConnected := (edidErr == nil && len(edidData) > 16) || connectedDisplays[connectorName] || connectedDisplays[name]
		if !isConnected {
			continue
		}

		display := shared.Display{
			Description:    connectorName,
			Manufacturer:   "Unknown",
			SerialNumber:   "Unknown",
			Model:          "Unknown",
			ConnectionType: linuxConnectionType(connectorName),
		}

		if edidErr == nil && len(edidData) > 16 {
			display.Manufacturer = parseEDIDManufacturer(edidData)
			display.SerialNumber = parseEDIDSerial(edidData)
			display.Model = parseEDIDModel(edidData)
			display.Size = parseEDIDSize(edidData)
			display.Year = parseEDIDYear(edidData)
			if w, h := parseEDIDNativeResolution(edidData); w > 0 && h > 0 {
				display.Resolution = fmt.Sprintf("%dx%d", w, h)
			}
		}

		if display.SerialNumber == "Unknown" || display.SerialNumber == "" || display.Model == "Unknown" {
			if edidDecodeOutput, err := shared.RunCommand("edid-decode", edidPath); err == nil {
				for _, line := range strings.Split(edidDecodeOutput, "\n") {
					if (display.SerialNumber == "Unknown" || display.SerialNumber == "") && strings.Contains(line, "Serial Number:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							serial := strings.TrimSpace(parts[1])
							if serial != "" && serial != "0" && serial != "Not specified" {
								display.SerialNumber = serial
							}
						}
					}
					if display.Model == "Unknown" && (strings.Contains(line, "Monitor Name:") || strings.Contains(line, "Model:")) {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							model := strings.TrimSpace(parts[1])
							if model != "" && len(model) > 2 {
								display.Model = model
							}
						}
					}
				}
			}
		}

		if display.SerialNumber == "Unknown" || display.SerialNumber == "" {
			if xrandrSerial := getSerialFromXrandrProps(connectorName); xrandrSerial != "" {
				display.SerialNumber = xrandrSerial
			}
		}

		if (display.SerialNumber == "Unknown" || display.SerialNumber == "") && strings.Contains(connectorName, "eDP") {
			if dmiSerial := getSerialFromDMI(); dmiSerial != "" {
				display.SerialNumber = dmiSerial
			}
		}

		if (display.SerialNumber == "Unknown" || display.SerialNumber == "") && edidErr == nil && len(edidData) > 16 {
			if edidHash := generateEDIDHash(edidData); edidHash != "" {
				display.SerialNumber = edidHash
			}
		}

		// xrandr current resolution takes priority over EDID native timing
		if xRes, ok := displayResolutions[connectorName]; ok {
			display.Resolution = xRes
		} else if xRes, ok := displayResolutions[name]; ok {
			display.Resolution = xRes
		}

		if refreshRate, ok := displayRefreshRates[connectorName]; ok {
			display.RefreshRate = refreshRate
		} else if refreshRate, ok := displayRefreshRates[name]; ok {
			display.RefreshRate = refreshRate
		}

		if display.Manufacturer == "" {
			display.Manufacturer = "Unknown"
		}
		if display.SerialNumber == "" {
			display.SerialNumber = "Unknown"
		}
		if display.Model == "" {
			display.Model = "Unknown"
		}
		displays = append(displays, display)
	}
	return displays
}

// parseEDIDNativeResolution extracts horizontal and vertical active pixels from
// the preferred timing descriptor (first 18-byte block at offset 54).
// Returns (0, 0) if the block is not a timing descriptor or the EDID is too short.
func parseEDIDNativeResolution(edid []byte) (width, height int) {
	if len(edid) < 72 {
		return 0, 0
	}
	// Non-zero pixel clock (bytes 54-55) distinguishes a timing descriptor
	// from a monitor descriptor block.
	if edid[54] == 0 && edid[55] == 0 {
		return 0, 0
	}
	width = int(edid[56]) | (int(edid[58]>>4) << 8)
	height = int(edid[59]) | (int(edid[61]>>4) << 8)
	if width <= 0 || height <= 0 {
		return 0, 0
	}
	return width, height
}

// parseEDIDYear returns the manufacture year encoded in EDID byte 17 (value + 1990).
func parseEDIDYear(edid []byte) int {
	if len(edid) < 18 {
		return 0
	}
	year := int(edid[17]) + 1990
	if year < 1990 || year > 2100 {
		return 0
	}
	return year
}

// linuxConnectionType maps a DRM connector name (e.g. "eDP-1", "HDMI-A-1", "DP-2")
// to a human-readable connection type.
func linuxConnectionType(connectorName string) string {
	lower := strings.ToLower(connectorName)
	switch {
	case strings.HasPrefix(lower, "edp"), strings.HasPrefix(lower, "lvds"), strings.HasPrefix(lower, "dsi"):
		return "Internal"
	case strings.HasPrefix(lower, "dp"):
		return "DisplayPort"
	case strings.HasPrefix(lower, "hdmi"):
		return "HDMI"
	case strings.HasPrefix(lower, "vga"):
		return "VGA"
	case strings.HasPrefix(lower, "dvi"):
		return "DVI"
	}
	return ""
}

func parseEDIDManufacturer(edid []byte) string {
	if len(edid) < 10 {
		return ""
	}
	b1, b2 := edid[8], edid[9]
	v1 := (int(b1) >> 2) & 0x1F
	v2 := ((int(b1) & 0x03) << 3) | (int(b2) >> 5)
	v3 := int(b2) & 0x1F
	return fmt.Sprintf("%c%c%c", v1+64, v2+64, v3+64)
}

func parseEDIDSerial(edid []byte) string {
	if len(edid) < 16 {
		return ""
	}
	for i := 54; i < 126; i += 18 {
		if i+17 >= len(edid) {
			break
		}
		if edid[i+3] == 0xFF {
			var serialBytes []byte
			for j := 5; j < 18; j++ {
				b := edid[i+j]
				if b == 0x0A || b == 0x20 {
					if len(serialBytes) > 0 {
						break
					}
					continue
				}
				if b >= 0x20 && b <= 0x7E {
					serialBytes = append(serialBytes, b)
				}
			}
			if len(serialBytes) > 0 {
				serial := string(serialBytes)
				if len(serial) > 3 && serial != "0123456789" && serial != "1234567890" {
					return serial
				}
			}
		}
	}
	serial := (int(edid[15]) << 24) | (int(edid[14]) << 16) | (int(edid[13]) << 8) | int(edid[12])
	if serial != 0 && serial != 1 {
		return fmt.Sprintf("%d", serial)
	}
	return generateEDIDHash(edid)
}

func generateEDIDHash(edid []byte) string {
	if len(edid) < 16 {
		return ""
	}
	var b strings.Builder
	for _, bt := range edid[8:16] {
		fmt.Fprintf(&b, "%02X", bt)
	}
	hash := b.String()
	if hash == "" || hash == "0000000000000000" {
		return ""
	}
	return hash
}

func parseEDIDModel(edid []byte) string {
	if len(edid) < 126 {
		return ""
	}
	for i := 54; i < 126; i += 18 {
		if i+17 >= len(edid) {
			break
		}
		if edid[i+3] == 0xFC {
			var modelBytes []byte
			for j := 5; j < 18; j++ {
				b := edid[i+j]
				if b == 0x0A {
					break
				}
				if b >= 0x20 && b <= 0x7E {
					modelBytes = append(modelBytes, b)
				}
			}
			if len(modelBytes) > 0 {
				model := strings.TrimRight(string(modelBytes), " ")
				if len(model) < 3 {
					continue
				}
				return model
			}
		}
	}
	manufacturer := parseEDIDManufacturer(edid)
	size := parseEDIDSize(edid)
	if manufacturer != "" && size > 0 {
		return fmt.Sprintf("%s %.0f\"", manufacturer, size)
	}
	return ""
}

func parseEDIDSize(edid []byte) float64 {
	if len(edid) < 25 {
		return 0
	}
	h := float64(edid[21])
	v := float64(edid[22])
	return math.Sqrt(h*h+v*v) / 2.54
}

func getSerialFromXrandrProps(connectorName string) string {
	output, err := shared.RunCommand("xrandr", "--prop", "--query")
	if err != nil {
		return ""
	}
	currentConnector := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, " connected") || strings.Contains(line, " disconnected") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				currentConnector = parts[0]
			}
			continue
		}
		if currentConnector == connectorName && strings.Contains(line, "EDID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				edidHex := strings.ReplaceAll(strings.TrimSpace(parts[1]), "\n", "")
				edidHex = strings.ReplaceAll(edidHex, " ", "")
				edidData, err := hex.DecodeString(edidHex)
				if err == nil && len(edidData) > 16 {
					if serial := parseEDIDSerial(edidData); serial != "" && serial != "Unknown" {
						return serial
					}
				}
			}
		}
	}
	return ""
}

func getSerialFromDMI() string {
	serial, err := shared.ReadFileContent("/sys/class/dmi/id/product_serial")
	if err != nil {
		return ""
	}
	serial = strings.TrimSpace(serial)
	if serial != "" && serial != "Not Specified" && serial != "Default String" && serial != "0123456789" {
		return serial
	}
	return ""
}
