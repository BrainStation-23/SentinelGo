package filescan

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
	"time"
)

// pdfBuilder writes a minimal PDF: objects in order, no xref table (the
// extractor doesn't need one).
type pdfBuilder struct {
	buf bytes.Buffer
}

func newPDF() *pdfBuilder {
	b := &pdfBuilder{}
	b.buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	return b
}

func (b *pdfBuilder) obj(num int, body string) *pdfBuilder {
	fmt.Fprintf(&b.buf, "%d 0 obj\n%s\nendobj\n", num, body)
	return b
}

// stream adds a stream object; flate compresses it.
func (b *pdfBuilder) stream(num int, dict string, data []byte, flate bool) *pdfBuilder {
	if flate {
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		_, _ = w.Write(data)
		_ = w.Close()
		data = z.Bytes()
		dict += " /Filter /FlateDecode"
	}
	fmt.Fprintf(&b.buf, "%d 0 obj\n<< %s /Length %d >>\nstream\n", num, dict, len(data))
	b.buf.Write(data)
	b.buf.WriteString("\nendstream\nendobj\n")
	return b
}

func (b *pdfBuilder) bytes(trailer string) []byte {
	fmt.Fprintf(&b.buf, "trailer\n<< %s >>\n%%%%EOF\n", trailer)
	return b.buf.Bytes()
}

// simplePDF is one page whose content stream is content, with font F1 a
// standard Type1 font.
func simplePDF(content string, flate bool) []byte {
	return newPDF().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >>").
		obj(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>").
		stream(4, "", []byte(content), flate).
		obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>").
		bytes("/Root 1 0 R")
}

func TestPDF_LiteralText(t *testing.T) {
	s := newTestScanner(t)
	for _, flate := range []bool{false, true} {
		pdf := simplePDF("BT /F1 12 Tf 72 700 Td (Card: "+testCard+") Tj ET", flate)
		res := scanBytes(t, s, pdf)
		if res.Status != StatusScanned || res.DetectedType != "pdf" || count(res.Findings, "pii.credit_card") != 1 {
			t.Errorf("flate=%v: %q %q %v", flate, res.Status, res.DetectedType, res.Findings)
		}
	}
}

func TestPDF_TJAndEscapes(t *testing.T) {
	s := newTestScanner(t)
	// TJ with kerning inside the number, an escaped paren and an octal escape
	content := `BT /F1 10 Tf [(4111 11)-20(11 1111 1111)] TJ T* [(TOP) 10 (SECRET)] TJ (\(ok\) \101) ' ET`
	res := scanBytes(t, s, simplePDF(content, true))
	if res.Status != StatusScanned || count(res.Findings, "pii.credit_card") != 1 || count(res.Findings, "kw") != 1 {
		t.Fatalf("%q %v", res.Status, res.Findings)
	}
}

func TestPDF_ToUnicodeCMap(t *testing.T) {
	// A Type0 font with 2-byte codes: digits mapped by a bfrange, space and
	// letters by bfchar. The codes alone are glyph ids, not text.
	cmap := `/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar <0003> <0020> <0024> <0043> endbfchar
1 beginbfrange <0013> <001C> <0030> endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end`
	enc := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch {
			case r == ' ':
				b.WriteString("0003")
			case r >= '0' && r <= '9':
				fmt.Fprintf(&b, "%04X", 0x13+int(r-'0'))
			}
		}
		return b.String()
	}
	pdf := newPDF().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>").
		obj(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F9 5 0 R >> >> >>").
		stream(4, "", []byte("BT /F9 11 Tf <"+enc(testCard)+"> Tj ET"), true).
		obj(5, "<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Calibri /Encoding /Identity-H /ToUnicode 6 0 R >>").
		stream(6, "", []byte(cmap), true).
		bytes("/Root 1 0 R")
	res := scanBytes(t, newTestScanner(t), pdf)
	if res.Status != StatusScanned || count(res.Findings, "pii.credit_card") != 1 {
		t.Fatalf("%q %v", res.Status, res.Findings)
	}
}

// Without a ToUnicode map, glyph ids aren't text: the result says the scan
// was partial instead of clean.
func TestPDF_UnmappedGlyphsAreTruncated(t *testing.T) {
	pdf := simplePDF("BT /F1 11 Tf <0013001400150016> Tj ET", true)
	res := scanBytes(t, newTestScanner(t), pdf)
	if res.Status != StatusTruncated {
		t.Fatalf("status %q, want truncated", res.Status)
	}
}

// Objects packed in an object stream (how Word saves PDFs) are found.
func TestPDF_ObjectStream(t *testing.T) {
	objs := []string{
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	nums := []int{2, 3, 5}
	var hdr, body strings.Builder
	for i, o := range objs {
		fmt.Fprintf(&hdr, "%d %d ", nums[i], body.Len())
		body.WriteString(o + "\n")
	}
	data := hdr.String() + body.String()
	pdf := newPDF().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		stream(4, "", []byte("BT /F1 12 Tf (TOPSECRET) Tj ET"), true).
		stream(9, fmt.Sprintf("/Type /ObjStm /N 3 /First %d", hdr.Len()), []byte(data), true).
		bytes("/Root 1 0 R")
	res := scanBytes(t, newTestScanner(t), pdf)
	if res.Status != StatusScanned || count(res.Findings, "kw") != 1 {
		t.Fatalf("%q %v", res.Status, res.Findings)
	}
}

func TestPDF_Encrypted(t *testing.T) {
	pdf := newPDF().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		stream(4, "", []byte("BT (x) Tj ET"), false).
		obj(7, "<< /Filter /Standard /V 4 /R 4 >>").
		bytes("/Root 1 0 R /Encrypt 7 0 R")
	res := scanBytes(t, newTestScanner(t), pdf)
	if res.Status != Unscannable(ReasonEncrypted) || len(res.Findings) != 0 {
		t.Fatalf("%q %v", res.Status, res.Findings)
	}
}

// A scanned document (an image, no text operators) is never reported clean.
func TestPDF_ImageOnlyIsUnsupported(t *testing.T) {
	pdf := newPDF().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		obj(3, "<< /Type /Page /Contents 4 0 R /Resources << /XObject << /Im1 5 0 R >> >> >>").
		stream(4, "", []byte("q 612 0 0 792 0 0 cm /Im1 Do Q"), true).
		stream(5, "/Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray", []byte{0}, true).
		bytes("/Root 1 0 R")
	res := scanBytes(t, newTestScanner(t), pdf)
	if res.Status != Unscannable(ReasonUnsupportedType) {
		t.Fatalf("status %q", res.Status)
	}
}

// A Flate bomb stops at the decompression budget instead of exhausting memory.
func TestPDF_FlateBomb(t *testing.T) {
	big := bytes.Repeat([]byte("BT (a) Tj ET "), 2<<20) // ~26 MB, compresses ~1000:1
	s := New(testEngine(t), Limits{MaxFileBytes: 1 << 20, MaxTextBytes: 1 << 20, MaxArchiveBytes: 4 << 20, MaxRatio: 100,
		MaxDepth: 3, MaxEntries: 100}, t.TempDir())
	res := scanBytes(t, s, simplePDF(string(big), true))
	if res.Status == StatusScanned {
		t.Fatalf("status %q: a bomb must not scan as complete", res.Status)
	}
}

// Inline image data isn't read as operators.
func TestPDF_InlineImageSkipped(t *testing.T) {
	content := "BI /W 4 /H 1 /BPC 8 /CS /G ID \x00(Tj)\xff EI BT /F1 9 Tf (" + testCard + ") Tj ET"
	res := scanBytes(t, newTestScanner(t), simplePDF(content, false))
	if res.Status != StatusScanned || count(res.Findings, "pii.credit_card") != 1 {
		t.Fatalf("%q %v", res.Status, res.Findings)
	}
}

func TestPDF_Damaged(t *testing.T) {
	pdf := simplePDF("BT /F1 12 Tf ("+testCard+") Tj ET", true)
	for _, cut := range []int{len(pdf) / 2, len(pdf) - 30, 20} {
		res := scanBytes(t, newTestScanner(t), pdf[:cut])
		if res.Status == "" {
			t.Errorf("cut %d: empty status", cut)
		}
	}
}

// Hostile structure costs linear time: many "trailer" words and packed
// objects that never close.
func TestPDF_PathologicalInputIsFast(t *testing.T) {
	s := newTestScanner(t)
	inputs := map[string][]byte{
		"trailers":     append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("trailer << /A (x "), 200000)...),
		"open objects": append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("1 0 obj << /A [ ("), 200000)...),
	}
	var hdr strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&hdr, "%d %d ", i+10, i*3)
	}
	packed := hdr.String() + strings.Repeat("<< ", 20000)
	inputs["packed objects"] = newPDF().
		stream(9, fmt.Sprintf("/Type /ObjStm /N 20000 /First %d", hdr.Len()), []byte(packed), true).
		bytes("")
	for name, in := range inputs {
		start := time.Now()
		res := scanBytes(t, s, in)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %v (%q)", name, d, res.Status)
		}
	}
}
