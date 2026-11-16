package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// minimalPE returns a PE32 image of size bytes: DOS header, PE header, one
// .text section, and zero padding after it as overlay.
func minimalPE(size int) []byte {
	b := make([]byte, size)
	le := binary.LittleEndian
	copy(b, "MZ")
	le.PutUint32(b[0x3c:], 0x40) // e_lfanew
	copy(b[0x40:], "PE\x00\x00")
	coff := 0x44
	le.PutUint16(b[coff:], 0x14c)    // Machine: i386
	le.PutUint16(b[coff+2:], 1)      // NumberOfSections
	le.PutUint16(b[coff+16:], 0xe0)  // SizeOfOptionalHeader
	le.PutUint16(b[coff+18:], 0x102) // Characteristics: executable, 32-bit
	opt := coff + 20
	le.PutUint16(b[opt:], 0x10b)       // PE32
	le.PutUint32(b[opt+16:], 0x1000)   // AddressOfEntryPoint
	le.PutUint32(b[opt+28:], 0x400000) // ImageBase
	le.PutUint32(b[opt+32:], 0x1000)   // SectionAlignment
	le.PutUint32(b[opt+36:], 0x200)    // FileAlignment
	le.PutUint16(b[opt+40:], 4)        // MajorOperatingSystemVersion
	le.PutUint16(b[opt+48:], 4)        // MajorSubsystemVersion
	le.PutUint32(b[opt+56:], 0x2000)   // SizeOfImage
	le.PutUint32(b[opt+60:], 0x200)    // SizeOfHeaders
	le.PutUint16(b[opt+68:], 3)        // Subsystem: console
	le.PutUint32(b[opt+92:], 16)       // NumberOfRvaAndSizes
	sec := opt + 0xe0
	copy(b[sec:], ".text")
	le.PutUint32(b[sec+8:], 0x1000)      // VirtualSize
	le.PutUint32(b[sec+12:], 0x1000)     // VirtualAddress
	le.PutUint32(b[sec+16:], 0x200)      // SizeOfRawData
	le.PutUint32(b[sec+20:], 0x200)      // PointerToRawData
	le.PutUint32(b[sec+36:], 0x60000020) // code, execute, read
	b[0x200] = 0xc3                      // ret
	return b
}

const peRules = `import "pe"
rule pe_header { condition: pe.is_pe and pe.number_of_sections == 1 and pe.sections[0].name == ".text" }
rule pe_full_input { condition: defined pe.calculate_checksum() }
`

func matchedRules(ms []Match) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		out[m.Rule] = true
	}
	return out
}

// A PE larger than go-yara's 64 KiB stream window is scanned whole, so
// fields needing the complete file (checksum, signatures) are defined.
func TestPEModuleScansWholeFile(t *testing.T) {
	p, skipped := compile(t, peRules, Options{})
	if len(skipped) != 0 || p.RuleCount() != 2 {
		t.Fatalf("rules = %d, skipped = %+v", p.RuleCount(), skipped)
	}
	for _, size := range []int{4 << 10, 200 << 10} {
		img := minimalPE(size)
		got := matchedRules(scan(t, p, string(img), File{Path: "a.exe", Size: int64(size)}))
		if !got["pe_header"] || !got["pe_full_input"] {
			t.Errorf("size %d: matched %v, want pe_header and pe_full_input", size, got)
		}
	}
}

// Over MaxWholePEBytes the file streams: headers still parse, whole-file
// fields stay undefined. Unknown size (0) streams too.
func TestPEModuleLargeOrUnknownSizeStreams(t *testing.T) {
	p, _ := compile(t, peRules, Options{})
	img := minimalPE(200 << 10)
	got := matchedRules(scan(t, p, string(img), File{Path: "a.exe"}))
	if !got["pe_header"] || got["pe_full_input"] {
		t.Errorf("unknown size: matched %v, want pe_header only", got)
	}
	if p.(*program).scanWhole(File{Type: "executable.pe", Size: MaxWholePEBytes + 1}) {
		t.Error("a PE over MaxWholePEBytes is read whole")
	}
}

// Rulesets that don't import pe never buffer, whatever the file.
func TestNoPEImportNeverBuffers(t *testing.T) {
	p, _ := compile(t, eicarRule, Options{})
	if p.(*program).scanWhole(File{Type: "executable.pe", Size: 1 << 20}) {
		t.Error("a ruleset without import \"pe\" reads PE files whole")
	}
	q, _ := compile(t, peRules, Options{})
	if q.(*program).scanWhole(File{Type: "text.utf8", Size: 1 << 20}) {
		t.Error("a non-PE file is read whole")
	}
}

// The whole-file read stops on cancellation instead of finishing the file.
func TestReadWholeHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readWhole(ctx, strings.NewReader(strings.Repeat("x", 3<<20)), 3<<20); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// A file that shrank since it was sized returns what is there.
	got, err := readWhole(context.Background(), strings.NewReader("abc"), 10)
	if err != nil || string(got) != "abc" {
		t.Errorf("short read = %q, %v", got, err)
	}
}
