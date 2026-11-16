package filescan

import (
	"encoding/binary"
	"strings"
	"testing"
)

// A real PE header wins over the text test; a bare "MZ" is still text.
func TestSniff_PEHeaderBeatsText(t *testing.T) {
	pe := []byte(strings.Repeat("A\x00", 512))
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x80)
	copy(pe[0x80:], "PE\x00\x00")
	if got := SniffType(pe); got != "executable.pe" {
		t.Errorf("PE with a UTF-16-looking stub = %q, want executable.pe", got)
	}
	if got := SniffType([]byte("MZ is a postcode prefix; this is a plain text file.")); got != "text.utf8" {
		t.Errorf("ASCII text starting with MZ = %q, want text.utf8", got)
	}
	for name, head := range map[string]string{
		"short":      "MZ",
		"bad lfanew": "MZ" + strings.Repeat("x", 0x3a) + "\xff\xff\xff\x7f" + strings.Repeat("y", 64),
		"no PE sig":  "MZ" + strings.Repeat("x", 0x3a) + "\x40\x00\x00\x00NOPE" + strings.Repeat("y", 64),
	} {
		if hasPEHeader([]byte(head)) {
			t.Errorf("%s: hasPEHeader = true", name)
		}
	}
}
