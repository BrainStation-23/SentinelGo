//go:build linux

package display

// Fuzz targets for EDID decoding. EDID blobs come from /sys/class/drm/*/edid
// and are whatever the attached monitor, KVM or HDMI dongle reports; the
// decoders index into them at fixed offsets, so malformed or truncated blobs
// must never panic and must not leak junk into the heartbeat payload.
//
// The seed corpus below runs as an ordinary unit test under `go test ./...`
// (Linux only). To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzApplyEDIDData$' -fuzztime=1m ./internal/osinfo/display/

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

var resolutionRe = regexp.MustCompile(`^[1-9][0-9]*x[1-9][0-9]*$`)

func edidSeeds() [][]byte {
	timing := [18]byte{0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40}
	valid := makeEDID(0x10, 0xAC, 1, 30, 52, 29, timing, "DELL U2722D", "SN12345")
	withExt := append(bytes.Clone(valid), 0x02, 0x03, 0x04) // truncated extension block
	garbage := bytes.Clone(valid)
	for i := 54; i < 126; i++ {
		garbage[i] = byte(i * 37)
	}
	return [][]byte{
		valid,
		makeEDID(0x10, 0xAC, 1, 30, 52, 29, [18]byte{}, "", ""),
		withExt,
		garbage,
		bytes.Repeat([]byte{0xFF}, 128),
		bytes.Repeat([]byte{0x00}, 128),
		valid[:127],
		valid[:72],
		valid[:25],
		valid[:16],
		valid[:10],
		{0x00},
		{},
		bytes.Repeat([]byte{0xFC}, 256),
	}
}

func FuzzApplyEDIDData(f *testing.F) {
	for _, s := range edidSeeds() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, edid []byte) {
		var d shared.Display
		applyEDIDData(&d, edid)

		if math.IsNaN(d.Size) || math.IsInf(d.Size, 0) || d.Size < 0 {
			t.Fatalf("Size = %v, want finite and >= 0", d.Size)
		}
		if d.Year != 0 && (d.Year < 1990 || d.Year > 2100) {
			t.Fatalf("Year = %d, want 0 or 1990..2100", d.Year)
		}
		if d.Resolution != "" && !resolutionRe.MatchString(d.Resolution) {
			t.Fatalf("Resolution = %q, want WxH with positive dimensions", d.Resolution)
		}
		for name, v := range map[string]string{
			"Manufacturer": d.Manufacturer, "SerialNumber": d.SerialNumber, "Model": d.Model,
		} {
			assertPrintableASCII(t, name, v)
		}
	})
}

func FuzzParseEDIDSize(f *testing.F) {
	for _, s := range edidSeeds() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, edid []byte) {
		size := parseEDIDSize(edid)
		if math.IsNaN(size) || math.IsInf(size, 0) || size < 0 {
			t.Fatalf("parseEDIDSize = %v, want finite and >= 0", size)
		}
		if size > 0 {
			// The fallback model name embeds the size; it must stay printable.
			assertPrintableASCII(t, "fallback model", fallbackEDIDModelName(edid))
		}
	})
}

func FuzzEDIDDecodeLine(f *testing.F) {
	for _, s := range []string{
		"    Serial Number: 'ABC123'",
		"    Display Product Serial Number: 'CN0ABC'",
		"    Display Product Name: 'DELL U2722D'",
		"    Monitor Name: DELL U2722D",
		"    Model: 41234",
		"Serial Number:",
		"Serial Number: 0",
		"Serial Number: Not specified",
		":",
		"",
		"\tEDID: 00ffffffffffff0010ac",
		"\tEDID: " + fmt.Sprintf("%x", edidSeeds()[0]),
		"\tEDID: zz",
		"\tEDID: 0",
		strings.Repeat("Model:", 1000),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		d := shared.Display{SerialNumber: "Unknown", Model: "Unknown"}
		applyEDIDDecodeLine(&d, line)
		_, _ = edidDecodeFieldValue(line)
		if serial, ok := serialFromXrandrEDIDLine(line); ok {
			assertPrintableASCII(t, "xrandr serial", serial)
		}
	})
}

func assertPrintableASCII(t *testing.T, field, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			t.Fatalf("%s = %q contains non-printable byte 0x%02X at %d", field, s, s[i], i)
		}
	}
}
