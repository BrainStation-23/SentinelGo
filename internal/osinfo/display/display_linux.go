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

// Test seams: production always runs the real commands against the real
// sysfs mount; tests swap these for fixture output and a t.TempDir() tree.
var (
	displayRunCommand = shared.RunCommand
	displaySysfsRoot  = "/sys"
)

// xrandrInfo bundles the per-connector state gathered from `xrandr --query`
// that buildLinuxDisplay layers on top of EDID data. Grouping these together
// keeps downstream function signatures short.
type xrandrInfo struct {
	connected    map[string]bool
	resolutions  map[string]string
	refreshRates map[string]float64
}

func getDisplays() []shared.Display {
	var displays []shared.Display

	xr := xrandrInfo{
		connected:    make(map[string]bool),
		resolutions:  make(map[string]string),
		refreshRates: make(map[string]float64),
	}
	if output, err := displayRunCommand("xrandr", "--query"); err == nil {
		xr.connected, xr.resolutions, xr.refreshRates = parseXrandrQuery(output)
	}

	drmDirs, err := os.ReadDir(displaySysfsRoot + "/class/drm")
	if err != nil {
		return displays
	}
	for _, dir := range drmDirs {
		name := dir.Name()
		if !isDRMConnectorName(name) {
			continue
		}
		if d, ok := buildLinuxDisplay(name, xr); ok {
			displays = append(displays, d)
		}
	}
	return displays
}

// parseXrandrQuery parses the full output of `xrandr --query` into the
// connected-connector set plus their current resolution and refresh rate,
// keyed by connector name (e.g. "DP-1").
func parseXrandrQuery(output string) (connected map[string]bool, resolutions map[string]string, refreshRates map[string]float64) {
	connected = make(map[string]bool)
	resolutions = make(map[string]string)
	refreshRates = make(map[string]float64)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, " connected") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		name := parts[0]
		connected[name] = true
		res, refresh, refreshSet := parseXrandrConnectedTokens(parts[1:])
		if res != "" {
			resolutions[name] = res
		}
		if refreshSet {
			refreshRates[name] = refresh
		}
	}
	return connected, resolutions, refreshRates
}

// parseXrandrConnectedTokens scans the fields following a connector name on an
// "xrandr --query" connected line for the active geometry ("NxM+X+Y") and, as
// a compatibility fallback, a refresh-rate token from mode lines.
func parseXrandrConnectedTokens(parts []string) (resolution string, refreshRate float64, refreshSet bool) {
	for _, part := range parts {
		// Geometry token: "NxM+X+Y" — current active mode
		if plusIdx := strings.Index(part, "+"); plusIdx > 0 {
			resolution = parseXrandrGeometry(part[:plusIdx])
			break
		}
		// Refresh rate on mode lines (indented) — won't appear here,
		// but kept for compatibility with non-standard xrandr output
		if strings.Contains(part, "*") || strings.Contains(part, "+") {
			rateStr := strings.TrimSuffix(strings.TrimSuffix(part, "*"), "+")
			if rate, err := strconv.ParseFloat(rateStr, 64); err == nil {
				refreshRate = rate
				refreshSet = true
			}
		}
	}
	return resolution, refreshRate, refreshSet
}

// parseXrandrGeometry validates that res looks like "NxM" (both dimensions
// numeric) before returning it as a resolution string.
func parseXrandrGeometry(res string) string {
	if !strings.Contains(res, "x") {
		return ""
	}
	halves := strings.SplitN(res, "x", 2)
	if len(halves) != 2 {
		return ""
	}
	if _, err := strconv.Atoi(halves[0]); err != nil {
		return ""
	}
	if _, err := strconv.Atoi(halves[1]); err != nil {
		return ""
	}
	return res
}

// isDRMConnectorName reports whether a /sys/class/drm entry name looks like a
// display connector (e.g. "card1-DP-1") rather than a bare GPU card node.
func isDRMConnectorName(name string) bool {
	if strings.HasPrefix(name, "card") && !strings.Contains(name, "-") {
		return false
	}
	if !strings.Contains(name, "DP-") && !strings.Contains(name, "HDMI-") &&
		!strings.Contains(name, "VGA-") && !strings.Contains(name, "eDP-") &&
		!strings.HasSuffix(name, "-") {
		return false
	}
	return true
}

// drmConnectorName strips the "cardN-" prefix from a /sys/class/drm entry
// name, leaving the bare connector name (e.g. "DP-1").
func drmConnectorName(name string) string {
	if idx := strings.Index(name, "-"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// buildLinuxDisplay builds a shared.Display for one DRM connector, combining
// EDID data with xrandr's live connection/geometry state. ok is false if the
// connector has neither a valid EDID nor an xrandr "connected" entry.
func buildLinuxDisplay(name string, xr xrandrInfo) (shared.Display, bool) {
	connectorName := drmConnectorName(name)

	edidPath := fmt.Sprintf("%s/class/drm/%s/edid", displaySysfsRoot, name)
	edidData, edidErr := shared.ReadFileBytes(edidPath)
	hasEDID := edidErr == nil && len(edidData) > 16
	if !hasEDID && !xr.connected[connectorName] && !xr.connected[name] {
		return shared.Display{}, false
	}

	display := shared.Display{
		Description:    connectorName,
		Manufacturer:   "Unknown",
		SerialNumber:   "Unknown",
		Model:          "Unknown",
		ConnectionType: linuxConnectionType(connectorName),
	}

	if hasEDID {
		applyEDIDData(&display, edidData)
	}

	applyEDIDDecodeFallback(&display, edidPath)
	applyLinuxSerialFallbacks(&display, connectorName, edidData, hasEDID)
	applyXrandrGeometry(&display, connectorName, name, xr)
	fillLinuxDisplayDefaults(&display)

	return display, true
}

// applyEDIDData populates display from a validated EDID blob.
func applyEDIDData(display *shared.Display, edidData []byte) {
	display.Manufacturer = parseEDIDManufacturer(edidData)
	display.SerialNumber = parseEDIDSerial(edidData)
	display.Model = parseEDIDModel(edidData)
	display.Size = parseEDIDSize(edidData)
	display.Year = parseEDIDYear(edidData)
	if w, h := parseEDIDNativeResolution(edidData); w > 0 && h > 0 {
		display.Resolution = fmt.Sprintf("%dx%d", w, h)
	}
}

// isUnknownOrEmpty reports whether a display field still holds its
// placeholder default, meaning a better value hasn't been found yet.
func isUnknownOrEmpty(s string) bool {
	return s == "" || s == "Unknown"
}

// applyEDIDDecodeFallback shells out to `edid-decode` to recover a serial
// number or model name when the raw EDID parse didn't produce one.
func applyEDIDDecodeFallback(display *shared.Display, edidPath string) {
	if !isUnknownOrEmpty(display.SerialNumber) && !isUnknownOrEmpty(display.Model) {
		return
	}
	edidDecodeOutput, err := displayRunCommand("edid-decode", edidPath)
	if err != nil {
		return
	}
	lines := strings.Split(edidDecodeOutput, "\n")
	// Current edid-decode prints the monitor's own name and serial strings as
	// "Display Product Name: '...'" / "Display Product Serial Number: '...'"
	// descriptors, after the header's numeric "Model:"/"Serial Number:"
	// fields. Apply the descriptors first so they take precedence.
	for _, line := range lines {
		if strings.Contains(line, "Display Product Name:") || strings.Contains(line, "Display Product Serial Number:") {
			applyEDIDDecodeLine(display, line)
		}
	}
	for _, line := range lines {
		applyEDIDDecodeLine(display, line)
	}
}

// applyEDIDDecodeLine inspects one line of `edid-decode` output, filling in
// the serial number or model on display if that line carries one.
func applyEDIDDecodeLine(display *shared.Display, line string) {
	applySerialFromDecodeLine(display, line)
	applyModelFromDecodeLine(display, line)
}

// applySerialFromDecodeLine fills display.SerialNumber from an edid-decode
// "Serial Number:" / "Display Product Serial Number:" line, unless one is
// already set or the value is a placeholder.
func applySerialFromDecodeLine(display *shared.Display, line string) {
	if !isUnknownOrEmpty(display.SerialNumber) || !strings.Contains(line, "Serial Number:") {
		return
	}
	value, ok := edidDecodeFieldValue(line)
	if !ok || value == "" || value == "0" || value == "Not specified" {
		return
	}
	display.SerialNumber = value
}

// applyModelFromDecodeLine fills display.Model from an edid-decode
// "Display Product Name:"/"Monitor Name:"/"Model:" line, unless one is
// already set or the value is too short to be meaningful. A purely numeric
// value is rejected: edid-decode's "Model:" line is the numeric product code,
// not a name.
func applyModelFromDecodeLine(display *shared.Display, line string) {
	if !isUnknownOrEmpty(display.Model) {
		return
	}
	if !strings.Contains(line, "Display Product Name:") && !strings.Contains(line, "Monitor Name:") && !strings.Contains(line, "Model:") {
		return
	}
	value, ok := edidDecodeFieldValue(line)
	if !ok || len(value) <= 2 || isDecimalString(value) {
		return
	}
	display.Model = value
}

// isDecimalString reports whether s is non-empty and consists only of ASCII
// digits.
func isDecimalString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// edidDecodeFieldValue splits an "edid-decode" "Label: value" line and
// returns the trimmed value, without the single quotes current edid-decode
// puts around descriptor strings (e.g. "Display Product Name: 'DELL U2722D'").
func edidDecodeFieldValue(line string) (string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	value := strings.TrimSpace(parts[1])
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	return value, true
}

// applyLinuxSerialFallbacks tries, in order, xrandr connector properties, the
// system DMI product serial (for internal panels only), and finally a hash of
// the EDID bytes — each only if the serial number is still unset.
func applyLinuxSerialFallbacks(display *shared.Display, connectorName string, edidData []byte, hasEDID bool) {
	if isUnknownOrEmpty(display.SerialNumber) {
		if xrandrSerial := getSerialFromXrandrProps(connectorName); xrandrSerial != "" {
			display.SerialNumber = xrandrSerial
		}
	}

	if isUnknownOrEmpty(display.SerialNumber) && strings.Contains(connectorName, "eDP") {
		if dmiSerial := getSerialFromDMI(); dmiSerial != "" {
			display.SerialNumber = dmiSerial
		}
	}

	if isUnknownOrEmpty(display.SerialNumber) && hasEDID {
		if edidHash := generateEDIDHash(edidData); edidHash != "" {
			display.SerialNumber = edidHash
		}
	}
}

// applyXrandrGeometry overrides the EDID-derived resolution/refresh rate with
// xrandr's live values, which take priority since they reflect the active mode.
func applyXrandrGeometry(display *shared.Display, connectorName, name string, xr xrandrInfo) {
	if xRes, ok := xr.resolutions[connectorName]; ok {
		display.Resolution = xRes
	} else if xRes, ok := xr.resolutions[name]; ok {
		display.Resolution = xRes
	}

	if refreshRate, ok := xr.refreshRates[connectorName]; ok {
		display.RefreshRate = refreshRate
	} else if refreshRate, ok := xr.refreshRates[name]; ok {
		display.RefreshRate = refreshRate
	}
}

// fillLinuxDisplayDefaults restores the "Unknown" placeholder for any field
// that ended up as an empty string after all the fallback lookups.
func fillLinuxDisplayDefaults(display *shared.Display) {
	if display.Manufacturer == "" {
		display.Manufacturer = "Unknown"
	}
	if display.SerialNumber == "" {
		display.SerialNumber = "Unknown"
	}
	if display.Model == "" {
		display.Model = "Unknown"
	}
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
	if serial := findEDIDDescriptorSerial(edid); serial != "" {
		return serial
	}
	if serial := edidSerialNumberField(edid); serial != "" {
		return serial
	}
	return generateEDIDHash(edid)
}

// findEDIDDescriptorSerial scans the 18-byte monitor descriptor blocks
// (offsets 54, 72, 90, 108) for one tagged 0xFF (ASCII serial number) and
// returns its decoded text, or "" if none is usable.
func findEDIDDescriptorSerial(edid []byte) string {
	for i := 54; i < 126; i += 18 {
		if i+17 >= len(edid) {
			break
		}
		if edid[i+3] != 0xFF {
			continue
		}
		if serial := decodeEDIDDescriptorText(edid, i); serial != "" {
			return serial
		}
	}
	return ""
}

// decodeEDIDDescriptorText decodes the ASCII text stored in bytes 5-17 of the
// 18-byte descriptor block at offset i, rejecting empty or placeholder values.
func decodeEDIDDescriptorText(edid []byte, i int) string {
	var textBytes []byte
	for j := 5; j < 18; j++ {
		b := edid[i+j]
		if b == 0x0A || b == 0x20 {
			if len(textBytes) > 0 {
				break
			}
			continue
		}
		if b >= 0x20 && b <= 0x7E {
			textBytes = append(textBytes, b)
		}
	}
	if len(textBytes) == 0 {
		return ""
	}
	serial := string(textBytes)
	if len(serial) > 3 && serial != "0123456789" && serial != "1234567890" {
		return serial
	}
	return ""
}

// edidSerialNumberField reads the 32-bit little-endian serial number field
// (EDID bytes 12-15), treating 0 and 1 as "not set".
func edidSerialNumberField(edid []byte) string {
	serial := (int(edid[15]) << 24) | (int(edid[14]) << 16) | (int(edid[13]) << 8) | int(edid[12])
	if serial != 0 && serial != 1 {
		return fmt.Sprintf("%d", serial)
	}
	return ""
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
	if model := findEDIDDescriptorModel(edid); model != "" {
		return model
	}
	return fallbackEDIDModelName(edid)
}

// findEDIDDescriptorModel scans the monitor descriptor blocks for one tagged
// 0xFC (ASCII monitor name) and returns its decoded text.
func findEDIDDescriptorModel(edid []byte) string {
	for i := 54; i < 126; i += 18 {
		if i+17 >= len(edid) {
			break
		}
		if edid[i+3] != 0xFC {
			continue
		}
		if model := decodeEDIDModelText(edid, i); model != "" {
			return model
		}
	}
	return ""
}

// decodeEDIDModelText decodes the ASCII monitor name in bytes 5-17 of the
// descriptor block at offset i, rejecting names shorter than 3 characters.
func decodeEDIDModelText(edid []byte, i int) string {
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
	if len(modelBytes) == 0 {
		return ""
	}
	model := strings.TrimRight(string(modelBytes), " ")
	if len(model) < 3 {
		return ""
	}
	return model
}

// fallbackEDIDModelName synthesizes a model name from the manufacturer and
// physical size when no descriptor block supplied one.
func fallbackEDIDModelName(edid []byte) string {
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
	output, err := displayRunCommand("xrandr", "--prop", "--query")
	if err != nil {
		return ""
	}
	currentConnector := ""
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if connector, ok := xrandrConnectorLine(line); ok {
			currentConnector = connector
			continue
		}
		if currentConnector != connectorName {
			continue
		}
		if line == "EDID:" {
			// Real xrandr prints the EDID hex on the indented lines that
			// follow "EDID:" (16 bytes per line), not on the same line.
			var consumed int
			line, consumed = joinXrandrEDIDHexLines(line, lines[i+1:])
			i += consumed
		}
		if serial, ok := serialFromXrandrEDIDLine(line); ok {
			return serial
		}
	}
	return ""
}

// xrandrConnectorLine reports whether line starts a new connector section in
// `xrandr --prop --query` output ("<name> connected ..." / "... disconnected ...").
func xrandrConnectorLine(line string) (connector string, ok bool) {
	if !strings.Contains(line, " connected") && !strings.Contains(line, " disconnected") {
		return "", false
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", false
	}
	return parts[0], true
}

// joinXrandrEDIDHexLines appends the hex-only continuation lines in rest to
// the "EDID:" header line, stopping at the first line that isn't pure hex. It
// returns the joined "EDID: <hex>" line and how many lines of rest it used.
func joinXrandrEDIDHexLines(header string, rest []string) (string, int) {
	var b strings.Builder
	b.WriteString(header)
	n := 0
	for _, l := range rest {
		l = strings.TrimSpace(l)
		if !isHexString(l) {
			break
		}
		b.WriteString(l)
		n++
	}
	return b.String(), n
}

// isHexString reports whether s is non-empty and consists only of hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// serialFromXrandrEDIDLine decodes an "EDID: <hex>" property line and
// extracts its serial number, if the EDID blob is long enough and valid.
func serialFromXrandrEDIDLine(line string) (string, bool) {
	if !strings.Contains(line, "EDID:") {
		return "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	edidHex := strings.ReplaceAll(strings.TrimSpace(parts[1]), "\n", "")
	edidHex = strings.ReplaceAll(edidHex, " ", "")
	edidData, err := hex.DecodeString(edidHex)
	if err != nil || len(edidData) <= 16 {
		return "", false
	}
	serial := parseEDIDSerial(edidData)
	if serial == "" || serial == "Unknown" {
		return "", false
	}
	return serial, true
}

func getSerialFromDMI() string {
	serial, err := shared.ReadFileContent(displaySysfsRoot + "/class/dmi/id/product_serial")
	if err != nil {
		return ""
	}
	serial = strings.TrimSpace(serial)
	if serial != "" && serial != "Not Specified" && serial != "Default String" && serial != "0123456789" {
		return serial
	}
	return ""
}
