//go:build linux

package display

// Hermetic tests for the Linux display collection pipeline. displayRunCommand
// returns fixture output for exactly the commands a test expects (anything
// else fails as "not installed"), and displaySysfsRoot points at a fake sysfs
// tree in t.TempDir(). Nothing here reads the host's /sys or runs xrandr.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func stubLinuxDisplayCommands(t *testing.T, outputs map[string]string) {
	t.Helper()
	orig := displayRunCommand
	t.Cleanup(func() { displayRunCommand = orig })
	displayRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		if out, ok := outputs[key]; ok {
			return out, nil
		}
		return "", errors.New("command not available: " + key)
	}
}

func stubLinuxDisplaySysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	orig := displaySysfsRoot
	t.Cleanup(func() { displaySysfsRoot = orig })
	displaySysfsRoot = root
	return root
}

// addDRMConnector creates <root>/class/drm/<name>/ and, when edid is non-nil,
// its edid file. It returns the edid path as getDisplays will compute it.
func addDRMConnector(t *testing.T, root, name string, edid []byte) string {
	t.Helper()
	dir := filepath.Join(root, "class", "drm", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := root + "/class/drm/" + name + "/edid"
	if edid != nil {
		if err := os.WriteFile(p, edid, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func writeDMISerial(t *testing.T, root, serial string) {
	t.Helper()
	dir := filepath.Join(root, "class", "dmi", "id")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "product_serial"), []byte(serial), 0o600); err != nil {
		t.Fatal(err)
	}
}

const xrandrQueryFixture = `Screen 0: minimum 320 x 200, current 3840 x 1080, maximum 16384 x 16384
eDP-1 connected primary 2560x1440+0+0 (normal left inverted right x axis y axis) 309mm x 174mm
   2560x1440     60.01*+  59.97    59.96
HDMI-A-1 connected 1920x1080+2560+0 (normal left inverted right x axis y axis) 527mm x 296mm
   1920x1080     60.00*+  50.00    59.94
DP-1 disconnected (normal left inverted right x axis y axis)
`

func TestGetDisplays_NoDRM(t *testing.T) {
	stubLinuxDisplaySysfs(t)
	stubLinuxDisplayCommands(t, nil)
	if got := getDisplays(); len(got) != 0 {
		t.Fatalf("getDisplays() = %+v, want none without /sys/class/drm", got)
	}
}

func TestGetDisplays_EndToEnd(t *testing.T) {
	root := stubLinuxDisplaySysfs(t)

	// Internal panel with a complete EDID (model + serial descriptors).
	addDRMConnector(t, root, "card0-eDP-1",
		makeEDID(0x10, 0xAC, 1, 30, 31, 17, timing1920x1080, "DELL P2419H", "CFV9N99"))
	// External monitor without an EDID, but xrandr reports it connected.
	addDRMConnector(t, root, "card0-HDMI-A-1", nil)
	// Disconnected port: no EDID, not in xrandr -> skipped.
	addDRMConnector(t, root, "card0-DP-1", nil)
	// EDID with no identity bytes (8-15 zero) and no size: serial/model come
	// from the edid-decode fallback.
	blank := makeEDID(0, 0, 0, 30, 0, 0, timing1920x1080, "", "")
	dp2EDID := addDRMConnector(t, root, "card0-DP-2", blank)
	// Non-connector entries.
	addDRMConnector(t, root, "card0", nil)
	addDRMConnector(t, root, "renderD128", nil)
	addDRMConnector(t, root, "card0-Writeback-1", nil)

	stubLinuxDisplayCommands(t, map[string]string{
		"xrandr --query": xrandrQueryFixture,
		"edid-decode " + dp2EDID: "Block 0, Base EDID:\n" +
			"  Vendor & Product Identification:\n" +
			"    Serial Number: 0\n" +
			"    Serial Number: Not specified\n" +
			"    Serial Number: 7MT0123456\n" +
			"    Serial Number: SHOULD-NOT-OVERRIDE\n" +
			"  Display Descriptors:\n" +
			"    Monitor Name: X\n" +
			"    Monitor Name: ROG PG279Q\n" +
			"    Monitor Name: SHOULD-NOT-OVERRIDE\n",
	})

	displays := getDisplays()
	byDesc := map[string]shared.Display{}
	for _, d := range displays {
		byDesc[d.Description] = d
	}
	if len(displays) != 3 {
		t.Fatalf("got %d displays (%+v), want eDP-1, HDMI-A-1, DP-2", len(displays), displays)
	}

	edp := byDesc["eDP-1"]
	if edp.Manufacturer != "DEL" || edp.Model != "DELL P2419H" || edp.SerialNumber != "CFV9N99" ||
		edp.ConnectionType != "Internal" || edp.Year != 2020 || edp.Size <= 0 {
		t.Errorf("eDP-1 = %+v", edp)
	}
	// xrandr's live mode overrides the EDID preferred timing.
	if edp.Resolution != "2560x1440" {
		t.Errorf("eDP-1 resolution = %q, want xrandr's 2560x1440", edp.Resolution)
	}

	hdmi := byDesc["HDMI-A-1"]
	if hdmi.Manufacturer != "Unknown" || hdmi.Model != "Unknown" || hdmi.SerialNumber != "Unknown" ||
		hdmi.ConnectionType != "HDMI" || hdmi.Resolution != "1920x1080" {
		t.Errorf("HDMI-A-1 = %+v", hdmi)
	}

	// The EDID parse leaves Model "" (not "Unknown"); edid-decode still fills it.
	dp2 := byDesc["DP-2"]
	if dp2.SerialNumber != "7MT0123456" || dp2.Model != "ROG PG279Q" ||
		dp2.ConnectionType != "DisplayPort" || dp2.Resolution != "1920x1080" {
		t.Errorf("DP-2 = %+v", dp2)
	}
}

func TestParseXrandrQuery(t *testing.T) {
	out := xrandrQueryFixture +
		// Non-standard line: a refresh token before the geometry.
		"XWAYLAND0 connected 59.95* 1280x800+0+0\n" +
		// Geometry token that isn't NxM.
		"VIRTUAL1 connected foo+0+0\n"
	connected, res, rates := parseXrandrQuery(out)

	for _, name := range []string{"eDP-1", "HDMI-A-1", "XWAYLAND0", "VIRTUAL1"} {
		if !connected[name] {
			t.Errorf("%s not reported connected", name)
		}
	}
	if connected["DP-1"] {
		t.Error("disconnected DP-1 reported connected")
	}
	if res["eDP-1"] != "2560x1440" || res["HDMI-A-1"] != "1920x1080" || res["XWAYLAND0"] != "1280x800" {
		t.Errorf("resolutions = %v", res)
	}
	if _, ok := res["VIRTUAL1"]; ok {
		t.Errorf("invalid geometry recorded: %q", res["VIRTUAL1"])
	}
	if rates["XWAYLAND0"] != 59.95 {
		t.Errorf("refresh rates = %v, want XWAYLAND0=59.95", rates)
	}
}

func TestParseXrandrGeometry(t *testing.T) {
	cases := map[string]string{
		"1920x1080": "1920x1080",
		"1920":      "",
		"axb":       "",
		"1920xb":    "",
	}
	for in, want := range cases {
		if got := parseXrandrGeometry(in); got != want {
			t.Errorf("parseXrandrGeometry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyXrandrGeometry_FallsBackToFullName(t *testing.T) {
	xr := xrandrInfo{
		resolutions:  map[string]string{"card0-DP-1": "3840x2160"},
		refreshRates: map[string]float64{"card0-DP-1": 144},
	}
	var d shared.Display
	applyXrandrGeometry(&d, "DP-1", "card0-DP-1", xr)
	if d.Resolution != "3840x2160" || d.RefreshRate != 144 {
		t.Errorf("got %+v", d)
	}

	xr = xrandrInfo{refreshRates: map[string]float64{"DP-1": 75}}
	applyXrandrGeometry(&d, "DP-1", "card0-DP-1", xr)
	if d.RefreshRate != 75 {
		t.Errorf("connector-name refresh rate not preferred: %+v", d)
	}
}

func TestIsDRMConnectorName(t *testing.T) {
	cases := map[string]bool{
		"card0":             false,
		"card1-DP-1":        true,
		"card1-eDP-1":       true,
		"card0-HDMI-A-1":    true,
		"card0-VGA-1":       true,
		"card0-Writeback-1": false,
		"renderD128":        false,
		"version":           false,
		"card0-":            true,
	}
	for in, want := range cases {
		if got := isDRMConnectorName(in); got != want {
			t.Errorf("isDRMConnectorName(%q) = %v, want %v", in, got, want)
		}
	}
	if got := drmConnectorName("plain"); got != "plain" {
		t.Errorf("drmConnectorName(plain) = %q", got)
	}
}

func TestGetSerialFromXrandrProps(t *testing.T) {
	edid := makeEDID(0x10, 0xAC, 1, 30, 52, 29, timing1920x1080, "DELL U2722D", "XR98765")
	edidHex := hex.EncodeToString(edid)

	out := "Screen 0: minimum 320 x 200, current 1920 x 1080, maximum 16384 x 16384\n" +
		"eDP-1 connected primary 1920x1080+0+0 (normal) 309mm x 174mm\n" +
		"\tEDID: zz-not-hex\n" +
		"\tnon-desktop: 0\n" +
		"DP-1 disconnected (normal left inverted right x axis y axis)\n" +
		"\tEDID: 00ff\n" +
		"HDMI-A-1 connected 1920x1080+1920+0 (normal) 527mm x 296mm\n" +
		"\tBroadcast RGB: Automatic\n" +
		"\tEDID: " + edidHex + "\n"

	stubLinuxDisplayCommands(t, map[string]string{"xrandr --prop --query": out})

	if got := getSerialFromXrandrProps("HDMI-A-1"); got != "XR98765" {
		t.Errorf("HDMI-A-1 serial = %q, want XR98765", got)
	}
	if got := getSerialFromXrandrProps("eDP-1"); got != "" {
		t.Errorf("eDP-1 (invalid hex) serial = %q, want empty", got)
	}
	if got := getSerialFromXrandrProps("DP-1"); got != "" {
		t.Errorf("DP-1 (short EDID) serial = %q, want empty", got)
	}
	if got := getSerialFromXrandrProps("DP-9"); got != "" {
		t.Errorf("unknown connector serial = %q, want empty", got)
	}

	stubLinuxDisplayCommands(t, nil)
	if got := getSerialFromXrandrProps("HDMI-A-1"); got != "" {
		t.Errorf("serial without xrandr = %q, want empty", got)
	}
}

func TestSerialFromXrandrEDIDLine(t *testing.T) {
	// An EDID whose only identity is zero yields no serial.
	zero := make([]byte, 128)
	if s, ok := serialFromXrandrEDIDLine("EDID: " + hex.EncodeToString(zero)); ok {
		t.Errorf("all-zero EDID produced serial %q", s)
	}
	if _, ok := serialFromXrandrEDIDLine("Broadcast RGB: Automatic"); ok {
		t.Error("non-EDID line accepted")
	}
}

func TestGetSerialFromDMI(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		stubLinuxDisplaySysfs(t)
		if got := getSerialFromDMI(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	cases := map[string]string{
		"PF2ABCDE\n":     "PF2ABCDE",
		"Not Specified":  "",
		"Default String": "",
		"0123456789":     "",
		"   \n":          "",
	}
	for content, want := range cases {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			root := stubLinuxDisplaySysfs(t)
			writeDMISerial(t, root, content)
			if got := getSerialFromDMI(); got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestApplyLinuxSerialFallbacks(t *testing.T) {
	t.Run("xrandr property wins", func(t *testing.T) {
		stubLinuxDisplaySysfs(t)
		edid := makeEDID(0x10, 0xAC, 1, 30, 52, 29, timing1920x1080, "", "XRSERIAL1")
		stubLinuxDisplayCommands(t, map[string]string{
			"xrandr --prop --query": "DP-1 connected 1920x1080+0+0\n\tEDID: " + hex.EncodeToString(edid) + "\n",
		})
		d := shared.Display{SerialNumber: "Unknown"}
		applyLinuxSerialFallbacks(&d, "DP-1", nil, false)
		if d.SerialNumber != "XRSERIAL1" {
			t.Errorf("serial = %q", d.SerialNumber)
		}
	})
	t.Run("internal panel uses DMI serial", func(t *testing.T) {
		root := stubLinuxDisplaySysfs(t)
		writeDMISerial(t, root, "LAPTOP-SN-42\n")
		stubLinuxDisplayCommands(t, nil)
		d := shared.Display{SerialNumber: ""}
		applyLinuxSerialFallbacks(&d, "eDP-1", nil, false)
		if d.SerialNumber != "LAPTOP-SN-42" {
			t.Errorf("serial = %q", d.SerialNumber)
		}
	})
	t.Run("external panel ignores DMI, hashes EDID", func(t *testing.T) {
		root := stubLinuxDisplaySysfs(t)
		writeDMISerial(t, root, "LAPTOP-SN-42\n")
		stubLinuxDisplayCommands(t, nil)
		edid := make([]byte, 20)
		edid[8], edid[9] = 0x10, 0xAC
		d := shared.Display{SerialNumber: "Unknown"}
		applyLinuxSerialFallbacks(&d, "DP-1", edid, true)
		if d.SerialNumber != "10AC000000000000" {
			t.Errorf("serial = %q, want EDID hash", d.SerialNumber)
		}
	})
	t.Run("nothing available", func(t *testing.T) {
		stubLinuxDisplaySysfs(t)
		stubLinuxDisplayCommands(t, nil)
		d := shared.Display{SerialNumber: "Unknown"}
		applyLinuxSerialFallbacks(&d, "eDP-1", make([]byte, 20), true)
		if d.SerialNumber != "Unknown" {
			t.Errorf("serial = %q, want Unknown", d.SerialNumber)
		}
	})
}

func TestApplyEDIDDecodeFallback_FillsModel(t *testing.T) {
	stubLinuxDisplayCommands(t, map[string]string{
		"edid-decode /x/edid": "    Model: 12\n    Monitor Name: ROG PG279Q\n    Model: 23305\n",
	})
	d := shared.Display{SerialNumber: "SN1", Model: "Unknown"}
	applyEDIDDecodeFallback(&d, "/x/edid")
	if d.Model != "ROG PG279Q" || d.SerialNumber != "SN1" {
		t.Errorf("got %+v", d)
	}

	// edid-decode missing leaves the display untouched.
	stubLinuxDisplayCommands(t, nil)
	d = shared.Display{SerialNumber: "", Model: "Unknown"}
	applyEDIDDecodeFallback(&d, "/x/edid")
	if d.Model != "Unknown" || d.SerialNumber != "" {
		t.Errorf("got %+v", d)
	}

	if _, ok := edidDecodeFieldValue("no separator"); ok {
		t.Error("edidDecodeFieldValue accepted a line without ':'")
	}
}

func TestApplyEDIDDecodeFallback_SkippedWhenComplete(t *testing.T) {
	called := false
	orig := displayRunCommand
	t.Cleanup(func() { displayRunCommand = orig })
	displayRunCommand = func(string, ...string) (string, error) {
		called = true
		return "", nil
	}
	d := shared.Display{SerialNumber: "SN1", Model: "Model"}
	applyEDIDDecodeFallback(&d, "/nonexistent/edid")
	if called {
		t.Error("edid-decode run although serial and model were known")
	}
}

func TestEDIDDecoders_EdgeCases(t *testing.T) {
	if got := parseEDIDSerial(make([]byte, 4)); got != "" {
		t.Errorf("parseEDIDSerial(short) = %q", got)
	}
	if got := generateEDIDHash(make([]byte, 4)); got != "" {
		t.Errorf("generateEDIDHash(short) = %q", got)
	}
	if got := parseEDIDModel(make([]byte, 64)); got != "" {
		t.Errorf("parseEDIDModel(short) = %q", got)
	}
	if got := parseEDIDSize(make([]byte, 10)); got != 0 {
		t.Errorf("parseEDIDSize(short) = %v", got)
	}

	// Numeric serial field (bytes 12-15) used when no 0xFF descriptor exists.
	e := makeEDID(0x10, 0xAC, 1, 30, 0, 0, [18]byte{}, "", "")
	e[12], e[13] = 0x39, 0x30 // 12345 little-endian
	if got := parseEDIDSerial(e); got != "12345" {
		t.Errorf("numeric serial = %q, want 12345", got)
	}

	// Placeholder descriptor serials are rejected and fall through.
	for _, placeholder := range []string{"0123456789", "1234567890", "ABC"} {
		e := makeEDID(0x10, 0xAC, 1, 30, 0, 0, [18]byte{}, "", placeholder)
		if got := parseEDIDSerial(e); got == placeholder {
			t.Errorf("placeholder serial %q accepted", placeholder)
		}
	}

}

func TestEDIDDescriptors_EdgeCases(t *testing.T) {
	// Descriptor of spaces only decodes to nothing.
	e := makeEDID(0, 0, 0, 0, 0, 0, [18]byte{}, "", "")
	e[93] = 0xFF
	for i := 95; i < 108; i++ {
		e[i] = 0x20
	}
	if got := findEDIDDescriptorSerial(e); got != "" {
		t.Errorf("blank serial descriptor = %q", got)
	}

	// Short monitor names are rejected; the model falls back to mfr + size.
	e = makeEDID(0x10, 0xAC, 1, 30, 52, 29, [18]byte{}, "AB", "")
	if got := parseEDIDModel(e); got != `DEL 23"` {
		t.Errorf("fallback model = %q, want DEL 23\"", got)
	}
	// Empty name descriptor.
	e = makeEDID(0, 0, 0, 0, 0, 0, [18]byte{}, "", "")
	e[75] = 0xFC
	e[77] = 0x0A
	if got := findEDIDDescriptorModel(e); got != "" {
		t.Errorf("empty name descriptor = %q", got)
	}
	// Truncated EDID stops the descriptor scan without panicking.
	if got := findEDIDDescriptorSerial(make([]byte, 80)); got != "" {
		t.Errorf("truncated scan serial = %q", got)
	}
	if got := findEDIDDescriptorModel(make([]byte, 80)); got != "" {
		t.Errorf("truncated scan model = %q", got)
	}

	// Timing descriptor with a pixel clock but zero active size.
	e = makeEDID(0, 0, 0, 0, 0, 0, [18]byte{0x01}, "", "")
	if w, h := parseEDIDNativeResolution(e); w != 0 || h != 0 {
		t.Errorf("zero-size timing = %dx%d", w, h)
	}
	// Year byte that would exceed 2100.
	y := make([]byte, 18)
	y[17] = 200
	if got := parseEDIDYear(y); got != 0 {
		t.Errorf("year 2190 = %d, want 0", got)
	}
}

func TestFillLinuxDisplayDefaults(t *testing.T) {
	d := shared.Display{}
	fillLinuxDisplayDefaults(&d)
	if d.Manufacturer != "Unknown" || d.SerialNumber != "Unknown" || d.Model != "Unknown" {
		t.Errorf("got %+v", d)
	}
}

// withEDIDChecksum sets byte 127 so the 128-byte base block sums to 0 mod 256,
// as a real EDID does.
func withEDIDChecksum(edid []byte) []byte {
	var sum byte
	for _, b := range edid[:127] {
		sum += b
	}
	edid[127] = -sum
	return edid
}

// xrandrPropEDIDBlock renders edid the way `xrandr --prop` does: "\tEDID: "
// alone on a line, then 16 bytes (32 hex chars) per "\t\t"-indented line.
func xrandrPropEDIDBlock(edid []byte) string {
	h := hex.EncodeToString(edid)
	var b strings.Builder
	b.WriteString("\tEDID: \n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString("\t\t" + h[i:i+32] + "\n")
	}
	return b.String()
}

// Regression for #119: real `xrandr --prop` output splits the EDID over eight
// indented continuation lines rather than putting it after "EDID:".
func TestGetSerialFromXrandrProps_MultiLineEDID(t *testing.T) {
	edid := withEDIDChecksum(makeEDID(0x10, 0xAC, 12, 31, 60, 34, timing1920x1080, "DELL U2722D", "CN0XR12345"))
	if !bytes.Equal(edid[:8], []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}) {
		t.Fatal("fixture EDID header invalid")
	}
	var sum byte
	for _, b := range edid {
		sum += b
	}
	if sum != 0 {
		t.Fatalf("fixture EDID checksum invalid: sum %d", sum)
	}

	other := withEDIDChecksum(makeEDID(0x4C, 0x2D, 1, 30, 52, 29, timing1920x1080, "SAMSUNG", "OTHER0001"))
	out := "Screen 0: minimum 320 x 200, current 3840 x 1080, maximum 16384 x 16384\n" +
		"eDP-1 connected primary 1920x1080+0+0 (normal left inverted right x axis y axis) 309mm x 174mm\n" +
		xrandrPropEDIDBlock(other) +
		"\tscaling mode: Full aspect \n" +
		"\t\tsupported: Full, Center, Full aspect\n" +
		"   1920x1080     60.02*+\n" +
		"HDMI-1 connected 1920x1080+1920+0 (normal left inverted right x axis y axis) 597mm x 336mm\n" +
		xrandrPropEDIDBlock(edid) +
		"\tnon-desktop: 0 \n" +
		"\t\tsupported: 0, 1\n" +
		"\tlink-status: Good \n" +
		"\t\tsupported: Good, Bad\n" +
		"   1920x1080     60.00*+  50.00    59.94\n" +
		"DP-1 disconnected (normal left inverted right x axis y axis)\n" +
		"\tnon-desktop: 0 \n" +
		"\t\tsupported: 0, 1\n"
	if got := strings.Count(out, "\t\t"+hex.EncodeToString(edid)[:32]); got != 1 {
		t.Fatalf("fixture malformed: %d", got)
	}
	stubLinuxDisplayCommands(t, map[string]string{"xrandr --prop --query": out})

	if got := getSerialFromXrandrProps("HDMI-1"); got != "CN0XR12345" {
		t.Errorf("HDMI-1 serial = %q, want CN0XR12345", got)
	}
	if got := getSerialFromXrandrProps("eDP-1"); got != "OTHER0001" {
		t.Errorf("eDP-1 serial = %q, want OTHER0001", got)
	}
	if got := getSerialFromXrandrProps("DP-1"); got != "" {
		t.Errorf("DP-1 (no EDID) serial = %q, want empty", got)
	}
}

// Regression for #119: an EDID with a serial but no name descriptor and no
// physical size parses to Model "" (not "Unknown"); edid-decode's monitor name
// must still fill it.
func TestGetDisplays_EDIDDecodeFillsEmptyModel(t *testing.T) {
	root := stubLinuxDisplaySysfs(t)
	nameless := withEDIDChecksum(makeEDID(0x10, 0xAC, 12, 31, 0, 0, timing1920x1080, "", "CN0XR12345"))
	if m := parseEDIDModel(nameless); m != "" {
		t.Fatalf("fixture precondition: parseEDIDModel = %q, want empty", m)
	}
	edidPath := addDRMConnector(t, root, "card0-DP-3", nameless)
	stubLinuxDisplayCommands(t, map[string]string{
		"edid-decode " + edidPath: "Block 0, Base EDID:\n" +
			"  EDID Structure Version & Revision: 1.4\n" +
			"  Vendor & Product Identification:\n" +
			"    Manufacturer: DEL\n" +
			"    Made in: week 12 of 2021\n" +
			"  Display Descriptors:\n" +
			"    Display Product Serial Number: 'CN0XR12345'\n" +
			"    Monitor Name: DELL U2722D\n",
	})

	displays := getDisplays()
	if len(displays) != 1 {
		t.Fatalf("got %d displays (%+v), want 1", len(displays), displays)
	}
	if d := displays[0]; d.Model != "DELL U2722D" || d.SerialNumber != "CN0XR12345" {
		t.Errorf("DP-3 = %+v, want Model DELL U2722D, Serial CN0XR12345", d)
	}
}

func TestApplyModelFromDecodeLine_EmptyModel(t *testing.T) {
	d := shared.Display{Model: ""}
	applyModelFromDecodeLine(&d, "    Monitor Name: DELL U2722D")
	if d.Model != "DELL U2722D" {
		t.Errorf("Model = %q, want DELL U2722D", d.Model)
	}
}

// modernEDIDDecodeFixture is current edid-decode output (format as printed by
// edid-decode 1.x): the header carries the numeric product code ("Model:") and
// serial field, while the name and serial strings live in quoted descriptors.
const modernEDIDDecodeFixture = `edid-decode (hex):

00 ff ff ff ff ff ff 00 10 ac 12 a1 4c 30 31 30
0c 1f 01 04 b5 3c 22 78 3b 4f 25 ae 52 4f 9e 26

----------------

Block 0, Base EDID:
  EDID Structure Version & Revision: 1.4
  Vendor & Product Identification:
    Manufacturer: DEL
    Model: 41234
    Serial Number: 808530252
    Made in: week 12 of 2021
  Basic Display Parameters & Features:
    Digital display
    Bits per primary color channel: 10
    DisplayPort interface
    Maximum image size: 60 cm x 34 cm
    Gamma: 2.20
  Standard Timings:
    DMT 0x52:  1920x1080   60.000000 Hz  16:9     67.500 kHz    148.500000 MHz
  Detailed Timing Descriptors:
    DTD 1:  1920x1080   60.000000 Hz  16:9     67.500 kHz    148.500000 MHz (600 mm x 340 mm)
                 Hfront   88 Hsync  44 Hback  148 Hpol P
                 Vfront    4 Vsync   5 Vback   36 Vpol P
    Display Product Serial Number: 'CN0XR12345'
    Display Product Name: 'DELL U2722D'
    Display Range Limits:
      Monitor ranges (GTF): 48-75 Hz V, 30-90 kHz H, max dotclock 170 MHz
  Extension blocks: 1
Checksum: 0x2c
`

// Modern edid-decode: the quoted descriptor strings must win over the
// header's numeric product code / serial field, with quotes stripped.
func TestApplyEDIDDecodeFallback_ModernFormat(t *testing.T) {
	stubLinuxDisplayCommands(t, map[string]string{"edid-decode /x/edid": modernEDIDDecodeFixture})
	d := shared.Display{SerialNumber: "Unknown", Model: ""}
	applyEDIDDecodeFallback(&d, "/x/edid")
	if d.Model != "DELL U2722D" || d.SerialNumber != "CN0XR12345" {
		t.Errorf("got Model %q, Serial %q; want DELL U2722D, CN0XR12345", d.Model, d.SerialNumber)
	}

	// Without the name descriptor, the numeric product code is still not a model.
	noName := strings.Replace(modernEDIDDecodeFixture, "    Display Product Name: 'DELL U2722D'\n", "", 1)
	stubLinuxDisplayCommands(t, map[string]string{"edid-decode /x/edid": noName})
	d = shared.Display{SerialNumber: "SN1", Model: ""}
	applyEDIDDecodeFallback(&d, "/x/edid")
	if d.Model != "" {
		t.Errorf("Model = %q, want empty (41234 is a product code)", d.Model)
	}
}

func TestEDIDDecodeLine_QuotedAndNumeric(t *testing.T) {
	d := shared.Display{SerialNumber: "Unknown", Model: "Unknown"}
	applyEDIDDecodeLine(&d, "    Display Product Serial Number: 'CN0XR12345'")
	applyEDIDDecodeLine(&d, "    Model: 41234")
	if d.SerialNumber != "CN0XR12345" || d.Model != "Unknown" {
		t.Errorf("got %+v", d)
	}
	applyEDIDDecodeLine(&d, "    Display Product Name: 'PRO AP241'")
	if d.Model != "PRO AP241" {
		t.Errorf("Model = %q, want PRO AP241", d.Model)
	}
}
