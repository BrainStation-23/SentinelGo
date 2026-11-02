package filescan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/policy"
)

const testCard = "4111 1111 1111 1111" // a Luhn-valid test card number

func testEngine(t testing.TB) *detect.Engine {
	t.Helper()
	eng, errs := detect.New([]detect.Rule{
		{DetectorID: "pii.credit_card", RuleID: "card", MinCount: 1},
		{DetectorID: "custom.keywords", RuleID: "kw", MinCount: 1, Keywords: []string{"TOPSECRET"}, CaseSensitive: true},
		{DetectorID: "custom.regex", RuleID: "num16", MinCount: 1, Pattern: `\b\d{16}\b`},
	}, policy.FileChunkBytes)
	if len(errs) > 0 {
		t.Fatalf("engine: %v", errs)
	}
	return eng
}

func testLimits() Limits {
	return LimitsFrom(policy.FilesModule{MaxFileBytes: policy.DefaultMaxFileBytes, MaxTextBytes: policy.DefaultMaxTextBytes, ScanTimeoutMs: 30000})
}

func newTestScanner(t testing.TB) *Scanner {
	return New(testEngine(t), testLimits(), t.TempDir())
}

func scanBytes(t testing.TB, s *Scanner, b []byte) Result {
	t.Helper()
	// A plain reader (not a ReaderAt), as an upload body would be.
	return s.Scan(context.Background(), Source{Size: int64(len(b))}, io.MultiReader(bytes.NewReader(b)))
}

func count(res []detect.Finding, rule string) int {
	n := 0
	for _, f := range res {
		if f.RuleID == rule || f.DetectorID == rule {
			n += f.Count
		}
	}
	return n
}

// zipOf builds a zip with the given entries, in order.
func zipOf(t testing.TB, entries ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func docx(t testing.TB, body string, extra ...[2]string) []byte {
	parts := [][2]string{
		{"[Content_Types].xml", `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`},
		{"word/document.xml", `<w:document xmlns:w="w"><w:body>` + body + `</w:body></w:document>`},
		{"word/styles.xml", `<w:styles xmlns:w="w"><w:name w:val="TOPSECRET style name is not text"/>TOPSECRET</w:styles>`},
	}
	return zipOf(t, append(parts, extra...)...)
}

func encodeUTF16(s string, bigEndian, bom bool) []byte {
	var b []byte
	if bom {
		if bigEndian {
			b = append(b, 0xfe, 0xff)
		} else {
			b = append(b, 0xff, 0xfe)
		}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return b
}

func TestScan_TextEncodings(t *testing.T) {
	s := newTestScanner(t)
	text := "Kunde: Müller\ncard " + testCard + "\nnote TOPSECRET 😀\n"
	latin1 := []byte("Kunde: M\xfcller\ncard " + testCard + "\nnote TOPSECRET\n")
	for _, tc := range []struct {
		name, typ string
		data      []byte
	}{
		{"utf8", "text.utf8", []byte(text)},
		{"utf8 bom", "text.utf8", append([]byte("\xef\xbb\xbf"), text...)},
		{"utf16le bom", "text.utf16le", encodeUTF16(text, false, true)},
		{"utf16be bom", "text.utf16be", encodeUTF16(text, true, true)},
		{"utf16le no bom", "text.utf16le", encodeUTF16(text, false, false)},
		{"utf16be no bom", "text.utf16be", encodeUTF16(text, true, false)},
		{"latin1", "text.latin1", latin1},
		{"csv starting like a bitmap", "text.utf8", []byte("BMW,Q3\nX," + testCard + ",TOPSECRET\n")},
	} {
		res := scanBytes(t, s, tc.data)
		if res.Status != StatusScanned || res.DetectedType != tc.typ {
			t.Errorf("%s: status %q type %q, want scanned %q", tc.name, res.Status, res.DetectedType, tc.typ)
		}
		if count(res.Findings, "pii.credit_card") != 1 || count(res.Findings, "kw") != 1 {
			t.Errorf("%s: findings %+v", tc.name, res.Findings)
		}
		sum := sha256.Sum256(tc.data)
		if res.SHA256 != hex.EncodeToString(sum[:]) || res.Size != int64(len(tc.data)) {
			t.Errorf("%s: sha %s size %d", tc.name, res.SHA256, res.Size)
		}
	}
}

// Characters split across reads (UTF-16 surrogate pairs and odd bytes,
// multi-byte UTF-8) decode the same as in one piece.
func TestDecodeText_SplitReads(t *testing.T) {
	text := strings.Repeat("ab😀c Müller TOPSECRET ", 4000) // several reads
	for _, tc := range []struct {
		enc  encoding
		data []byte
	}{
		{encUTF16LE, encodeUTF16(text, false, true)},
		{encUTF16BE, encodeUTF16(text, true, true)},
		{encUTF8, []byte(text)},
	} {
		if got := decodeAll(t, tc.data, tc.enc); got != text {
			t.Errorf("%s: decoded text differs (len %d vs %d)", tc.enc.name(), len(got), len(text))
		}
	}
	// An unpaired surrogate becomes U+FFFD instead of failing.
	if got := decodeAll(t, []byte{0x3d, 0xd8, 'a', 0}, encUTF16LE); got != "\ufffda" {
		t.Errorf("unpaired surrogate: %q", got)
	}
}

// oddReader returns 7 bytes at a time, to split characters across reads.
type oddReader struct {
	data []byte
	off  int
}

func (o *oddReader) Read(p []byte) (int, error) {
	if o.off >= len(o.data) {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), 7)], o.data[o.off:])
	o.off += n
	return n, nil
}

// decodeAll decodes data read 7 bytes at a time and returns the text.
func decodeAll(t *testing.T, data []byte, enc encoding) string {
	t.Helper()
	st := &scanState{s: &Scanner{chunk: 1 << 30, overlap: 4096}, ctx: context.Background(), textLeft: 1 << 30}
	sink := newSink(st)
	if err := decodeText(&oddReader{data: data}, enc, sink); err != nil {
		t.Fatal(err)
	}
	return string(sink.buf)
}

func TestSniff_Binary(t *testing.T) {
	s := newTestScanner(t)
	for _, tc := range []struct {
		name string
		data []byte
		typ  string
	}{
		{"png", append([]byte("\x89PNG\r\n\x1a\n"), testCard...), "image.png"},
		{"pdf", []byte("%PDF-1.7\n" + testCard), "pdf"},
		{"elf", append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 64)...), "executable.elf"},
		{"bmp", append([]byte("BM\x36\x00\x0c\x00\x00\x00\x00\x00"), make([]byte, 64)...), "image.bmp"},
		{"random bytes", bytes.Repeat([]byte{0x01, 0x92, 0x03, 0xfe}, 100), "binary"},
	} {
		res := scanBytes(t, s, tc.data)
		if res.Status != Unscannable(ReasonUnsupportedType) || res.DetectedType != tc.typ || len(res.Findings) != 0 {
			t.Errorf("%s: %q %q %v", tc.name, res.Status, res.DetectedType, res.Findings)
		}
	}
}

// The chunked scan finds exactly what one scan of the whole text finds, for
// matches anywhere relative to the chunk cuts.
func TestScan_ChunkBoundaries(t *testing.T) {
	eng := testEngine(t)
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "%s%s ", strings.Repeat("x", i%37), testCard)
		if i%3 == 0 {
			b.WriteString("TOPSECRET")
		}
		if i%5 == 0 {
			b.WriteString("\n")
		}
		if i%7 == 0 {
			b.WriteString("1234567812345670 ")
		}
	}
	text := b.String()
	whole := eng.Scan(text)
	if whole.Truncated {
		t.Fatal("reference scan truncated")
	}
	for _, chunk := range []int{64, 97, 256, 1000} {
		s := New(eng, testLimits(), "")
		s.chunk, s.overlap = chunk, 48
		res := scanBytes(t, s, []byte(text))
		for _, rule := range []string{"card", "kw", "num16"} {
			if got, want := count(res.Findings, rule), count(whole.Findings, rule); got != want {
				t.Errorf("chunk %d: %s count %d, want %d", chunk, rule, got, want)
			}
		}
		// Offsets point at the same text.
		for _, f := range res.Findings {
			for _, o := range f.Offsets {
				if o[1] > len(text) || o[0] < 0 {
					t.Fatalf("chunk %d: offset %v out of range", chunk, o)
				}
			}
		}
	}
}

func TestScan_TextLimit(t *testing.T) {
	lim := testLimits()
	lim.MaxTextBytes = 100
	s := New(testEngine(t), lim, "")
	data := []byte("card " + testCard + "\n" + strings.Repeat("filler ", 50) + "TOPSECRET")
	res := scanBytes(t, s, data)
	if res.Status != StatusTruncated || res.TextBytes != 100 {
		t.Errorf("status %q text %d", res.Status, res.TextBytes)
	}
	if count(res.Findings, "pii.credit_card") != 1 || count(res.Findings, "kw") != 0 {
		t.Errorf("findings %+v", res.Findings)
	}
	if res.SHA256 == "" {
		t.Error("the file was read in full but has no hash")
	}
}

func TestScan_OOXML(t *testing.T) {
	s := newTestScanner(t)
	// The card number is split over runs inside one paragraph, as Word does.
	doc := docx(t, `<w:p><w:r><w:t>Card 4111 1111</w:t></w:r><w:r><w:t xml:space="preserve"> 1111 1111</w:t></w:r></w:p>`+
		`<w:p><w:r><w:instrText>TOPSECRET field code</w:instrText></w:r></w:p>`,
		[2]string{"word/header1.xml", `<w:hdr xmlns:w="w"><w:p><w:r><w:t>TOPSECRET</w:t></w:r></w:p></w:hdr>`},
		[2]string{"docProps/custom.xml", `<Properties><property name="MSIP_Label_1234_Name"><vt:lpwstr>Confidential</vt:lpwstr></property>` +
			`<property name="MSIP_Label_1234_Enabled"><vt:lpwstr>true</vt:lpwstr></property></Properties>`})
	res := scanBytes(t, s, doc)
	if res.Status != StatusScanned || res.DetectedType != "ooxml.docx" {
		t.Fatalf("status %q type %q", res.Status, res.DetectedType)
	}
	if count(res.Findings, "pii.credit_card") != 1 {
		t.Errorf("card across runs: %+v", res.Findings)
	}
	// Once in the header; not from the field code or styles.xml.
	if count(res.Findings, "kw") != 1 {
		t.Errorf("keyword count %d", count(res.Findings, "kw"))
	}
	if len(res.Labels) != 1 || res.Labels[0] != "Confidential" {
		t.Errorf("labels %v", res.Labels)
	}
}

func TestScan_XLSX(t *testing.T) {
	s := newTestScanner(t)
	xlsx := zipOf(t,
		[2]string{"[Content_Types].xml", `<Types/>`},
		[2]string{"xl/workbook.xml", `<workbook/>`},
		[2]string{"xl/sharedStrings.xml", `<sst><si><t>TOPSECRET</t></si><si><t>customer</t></si></sst>`},
		// Two adjacent cells must not read as one 16-digit number; the
		// third cell's value is one; its formula text isn't scanned.
		[2]string{"xl/worksheets/sheet1.xml", `<worksheet><sheetData><row r="1"><c r="A1"><v>41111111</v></c><c r="B1"><v>11111111</v></c></row>` +
			`<row r="2"><c r="A2"><f>"1234567812345670"</f><v>4111111111111111</v></c></row></sheetData></worksheet>`},
	)
	res := scanBytes(t, s, xlsx)
	if res.DetectedType != "ooxml.xlsx" || res.Status != StatusScanned {
		t.Fatalf("status %q type %q", res.Status, res.DetectedType)
	}
	if count(res.Findings, "kw") != 1 || count(res.Findings, "num16") != 1 {
		t.Errorf("findings %+v", res.Findings)
	}
}

func TestScan_ODF(t *testing.T) {
	s := newTestScanner(t)
	odt := zipOf(t,
		[2]string{"mimetype", "application/vnd.oasis.opendocument.text"},
		[2]string{"content.xml", `<office:document-content><office:body><office:text><text:p>Card ` + testCard + `</text:p><text:p>TOPSECRET</text:p></office:text></office:body></office:document-content>`},
	)
	res := scanBytes(t, s, odt)
	if res.DetectedType != "odf.text" || res.Status != StatusScanned || count(res.Findings, "pii.credit_card") != 1 || count(res.Findings, "kw") != 1 {
		t.Errorf("odt: %q %q %+v", res.Status, res.DetectedType, res.Findings)
	}
	enc := zipOf(t,
		[2]string{"mimetype", "application/vnd.oasis.opendocument.spreadsheet"},
		[2]string{"META-INF/manifest.xml", `<manifest:manifest><manifest:file-entry><manifest:encryption-data/></manifest:file-entry></manifest:manifest>`},
		[2]string{"content.xml", `garbage`},
	)
	if res := scanBytes(t, s, enc); res.Status != Unscannable(ReasonPasswordProtected) || res.DetectedType != "odf.spreadsheet" {
		t.Errorf("encrypted ods: %q %q", res.Status, res.DetectedType)
	}
}

func TestScan_Archive(t *testing.T) {
	s := newTestScanner(t)
	inner := zipOf(t, [2]string{"deep/report.docx", string(docx(t, `<w:p><w:r><w:t>`+testCard+`</w:t></w:r></w:p>`))})
	outer := zipOf(t,
		[2]string{"readme.txt", "nothing here"},
		[2]string{"keys.txt", "TOPSECRET"},
		[2]string{"photo.png", "\x89PNG\r\n\x1a\n...."},
		[2]string{"inner.zip", string(inner)},
	)
	res := scanBytes(t, s, outer)
	if res.DetectedType != "archive.zip" {
		t.Fatalf("type %q", res.DetectedType)
	}
	// The png makes the archive's status unscannable (its worst entry).
	if res.Status != Unscannable(ReasonUnsupportedType) {
		t.Errorf("status %q", res.Status)
	}
	got := map[string]Entry{}
	for _, e := range res.Entries {
		got[e.Name] = e
	}
	if len(got) != 3 {
		t.Errorf("entries %+v", res.Entries)
	}
	if e := got["keys.txt"]; count(e.Findings, "kw") != 1 || e.Status != StatusScanned {
		t.Errorf("keys.txt: %+v", e)
	}
	if e := got["inner.zip/deep/report.docx"]; count(e.Findings, "pii.credit_card") != 1 || e.DetectedType != "ooxml.docx" {
		t.Errorf("nested docx: %+v", e)
	}
	if e := got["photo.png"]; e.Status != Unscannable(ReasonUnsupportedType) {
		t.Errorf("png: %+v", e)
	}
}

func TestScan_ArchiveLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		s := newTestScanner(t)
		z := zipOf(t, [2]string{"a.txt", "TOPSECRET"})
		for i := 0; i < DefaultMaxDepth+1; i++ {
			z = zipOf(t, [2]string{fmt.Sprintf("level%d.zip", i), string(z)})
		}
		res := scanBytes(t, s, z)
		if res.Status != Unscannable(ReasonTooLarge) {
			t.Errorf("status %q entries %+v", res.Status, res.Entries)
		}
	})
	t.Run("entries", func(t *testing.T) {
		lim := testLimits()
		lim.MaxEntries = 3
		s := New(testEngine(t), lim, "")
		var es [][2]string
		for i := 0; i < 5; i++ {
			es = append(es, [2]string{fmt.Sprintf("f%d.txt", i), "x"})
		}
		if res := scanBytes(t, s, zipOf(t, es...)); res.Status != Unscannable(ReasonTooLarge) {
			t.Errorf("status %q", res.Status)
		}
	})
	t.Run("bomb", func(t *testing.T) {
		s := newTestScanner(t)
		z := zipOf(t, [2]string{"zeros.txt", strings.Repeat("0", 20<<20)}) // ~1000:1
		res := scanBytes(t, s, z)
		if len(res.Entries) != 1 || res.Entries[0].Status != Unscannable(ReasonTooLarge) {
			t.Errorf("bomb: %q %+v", res.Status, res.Entries)
		}
	})
	t.Run("declared entry count", func(t *testing.T) {
		z := zipOf(t, [2]string{"a.txt", "x"})
		n, ok := zipEntryCount(bytes.NewReader(z), int64(len(z)))
		if !ok || n != 1 {
			t.Errorf("entry count %d %v", n, ok)
		}
		// Claim 60000 entries in the end record.
		bad := append([]byte(nil), z...)
		i := bytes.LastIndex(bad, []byte("PK\x05\x06"))
		bad[i+10], bad[i+11] = 0x60, 0xea
		s := newTestScanner(t)
		if res := scanBytes(t, s, bad); res.Status != Unscannable(ReasonTooLarge) {
			t.Errorf("status %q", res.Status)
		}
	})
}

func TestScan_EncryptedZipEntry(t *testing.T) {
	z := zipOf(t, [2]string{"secret.txt", "TOPSECRET"})
	// Set the "encrypted" flag on the entry in both headers.
	for _, sig := range []string{"PK\x03\x04", "PK\x01\x02"} {
		i := bytes.Index(z, []byte(sig))
		off := 6
		if sig == "PK\x01\x02" {
			off = 8
		}
		z[i+off] |= 1
	}
	res := scanBytes(t, newTestScanner(t), z)
	if res.Status != Unscannable(ReasonPasswordProtected) || len(res.Entries) != 1 || len(res.Entries[0].Findings) != 0 {
		t.Errorf("%q %+v", res.Status, res.Entries)
	}
}

func TestScan_Corrupt(t *testing.T) {
	res := scanBytes(t, newTestScanner(t), []byte("PK\x03\x04 this is not really a zip"))
	if res.Status != Unscannable(ReasonCorrupt) {
		t.Errorf("status %q", res.Status)
	}
	// A well-formed zip whose document part isn't XML: corrupt, not clean,
	// and the text before the error is still scanned.
	bad := docx(t, `<w:p><w:r><w:t>`+testCard+`</w:t></w:r></w:p><w:p><<<`)
	res = scanBytes(t, newTestScanner(t), bad)
	if res.Status != Unscannable(ReasonCorrupt) || count(res.Findings, "pii.credit_card") != 1 {
		t.Errorf("malformed part: %q %+v", res.Status, res.Findings)
	}
}

func cfbWith(names ...string) []byte {
	b := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), make([]byte, 600)...)
	for _, n := range names {
		b = append(b, utf16le(n)...)
		b = append(b, make([]byte, 100)...)
	}
	return b
}

func TestScan_CFB(t *testing.T) {
	s := newTestScanner(t)
	for _, tc := range []struct {
		name, status, typ string
		data              []byte
	}{
		{"password", Unscannable(ReasonPasswordProtected), "ooxml.encrypted", cfbWith("EncryptionInfo", "EncryptedPackage", "StrongEncryptionDataSpace")},
		{"rights management", Unscannable(ReasonRightsProtected), "ooxml.encrypted", cfbWith("EncryptedPackage", "DRMEncryptedDataSpace")},
		{"legacy doc", Unscannable(ReasonUnsupportedType), "ole", cfbWith("WordDocument", "1Table")},
	} {
		if res := scanBytes(t, s, tc.data); res.Status != tc.status || res.DetectedType != tc.typ {
			t.Errorf("%s: %q %q", tc.name, res.Status, res.DetectedType)
		}
	}
}

func TestScan_RTF(t *testing.T) {
	s := newTestScanner(t)
	rtf := `{\rtf1\ansi\ansicpg1252\uc1{\fonttbl{\f0 TOPSECRET Font;}}{\*\generator TOPSECRET}` +
		`{\info{\author TOPSECRET}}\pard Caf\'e9 card 4111\~1111 1111 1111\par ` +
		`\u8364? euro {\*\unknowndest TOPSECRET} TOP\b SECRET\b0 and TOPSECRET\par}`
	res := scanBytes(t, s, []byte(rtf))
	if res.DetectedType != "rtf" || res.Status != StatusScanned {
		t.Fatalf("%q %q", res.Status, res.DetectedType)
	}
	// "4111\~1111" is a non-breaking space: still the card number.
	if count(res.Findings, "pii.credit_card") != 1 {
		t.Errorf("card: %+v", res.Findings)
	}
	// Only the last one: font table, generator, info and the unknown
	// destination are skipped; "TOP\b SECRET" reads as "TOPSECRET" too.
	if count(res.Findings, "kw") != 2 {
		t.Errorf("keyword count %d", count(res.Findings, "kw"))
	}
	st := &scanState{s: &Scanner{chunk: 1 << 30, overlap: 4096}, ctx: context.Background(), textLeft: 1 << 30}
	sink := newSink(st)
	if err := extractRTF(strings.NewReader(rtf), sink); err != nil {
		t.Fatal(err)
	}
	if got := string(sink.buf); !strings.Contains(got, "Café") || !strings.Contains(got, "€ euro") || strings.Contains(got, "?") {
		t.Errorf("text %q", got)
	}
	deep := "{\\rtf1 " + strings.Repeat("{", rtfMaxDepth+5) + "x"
	if res := scanBytes(t, s, []byte(deep)); res.Status != Unscannable(ReasonCorrupt) {
		t.Errorf("deep nesting: %q", res.Status)
	}
}

// panicReader fails the test if it is read.
type panicReader struct{ t *testing.T }

func (p panicReader) Read([]byte) (int, error) {
	p.t.Fatal("read a file that is over the size limit")
	return 0, nil
}

func TestScan_TooLarge(t *testing.T) {
	lim := testLimits()
	lim.MaxFileBytes = 1000
	s := New(testEngine(t), lim, t.TempDir())
	if res := s.Scan(context.Background(), Source{Size: 1001}, panicReader{t}); res.Status != Unscannable(ReasonTooLarge) {
		t.Errorf("declared size: %q", res.Status)
	}
	// An unknown size that turns out too big.
	if res := s.Scan(context.Background(), Source{Size: -1}, bytes.NewReader(bytes.Repeat([]byte("a "), 600))); res.Status != Unscannable(ReasonTooLarge) {
		t.Errorf("streamed: %q", res.Status)
	}
}

// blockingReader returns data until it reaches its end, then waits until ctx
// is done.
type blockingReader struct {
	ctx  context.Context
	data []byte
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func TestScan_Timeout(t *testing.T) {
	lim := testLimits()
	lim.Timeout = 50 * time.Millisecond
	s := New(testEngine(t), lim, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res := s.Scan(context.Background(), Source{Size: -1}, &blockingReader{ctx: ctxWithTimeout(t, lim.Timeout), data: []byte("TOPSECRET")})
	if res.Status != StatusTimeout || time.Since(start) > 2*time.Second {
		t.Errorf("status %q after %v", res.Status, time.Since(start))
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if res := s.Scan(cancelled, Source{Size: 9}, strings.NewReader("TOPSECRET")); res.Status != StatusTimeout {
		t.Errorf("cancelled: %q", res.Status)
	}
}

func ctxWithTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// Inputs over the memory limit are spilled to spillDir and the spill file is
// gone after the scan; without a spill dir they can't be scanned.
func TestScan_Spill(t *testing.T) {
	dir := t.TempDir()
	lim := testLimits()
	lim.MaxTextBytes = policy.MaxTextBytesLimit
	s := New(testEngine(t), lim, dir)
	// Text that doesn't compress past the bomb ratio when zipped.
	var b strings.Builder
	for i := 0; b.Len() < memSpillLimit+1000; i++ {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		fmt.Fprintf(&b, "%x\n", sum[:12])
	}
	data := []byte(b.String() + "TOPSECRET\n")
	inner := zipOf(t, [2]string{"big.txt", string(data)})
	for name, in := range map[string][]byte{"text": data, "zip": inner} {
		res := scanBytes(t, s, in)
		if count(res.Findings, "kw")+countEntries(res.Entries, "kw") != 1 {
			t.Errorf("%s: %q %+v %+v", name, res.Status, res.Findings, res.Entries)
		}
		left, _ := os.ReadDir(dir)
		if len(left) != 0 {
			t.Errorf("%s: spill files left: %v", name, left)
		}
	}
	noSpill := New(testEngine(t), lim, "")
	if res := scanBytes(t, noSpill, data); res.Status != Unscannable(ReasonTooLarge) {
		t.Errorf("without spill dir: %q", res.Status)
	}
}

func countEntries(es []Entry, rule string) int {
	n := 0
	for _, e := range es {
		n += count(e.Findings, rule)
	}
	return n
}

// An *os.File is read in place (no spill) and hashed.
func TestScan_File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.xlsx.jpg") // renamed: the type comes from the content
	data := docx(t, `<w:p><w:r><w:t>TOPSECRET</w:t></w:r></w:p>`)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	res := New(testEngine(t), testLimits(), "").Scan(context.Background(), Source{Size: int64(len(data))}, f)
	sum := sha256.Sum256(data)
	if res.DetectedType != "ooxml.docx" || count(res.Findings, "kw") != 1 || res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("%q %+v %s", res.DetectedType, res.Findings, res.SHA256)
	}
}

func TestScan_NoEngine(t *testing.T) {
	res := scanBytes(t, New(nil, testLimits(), ""), []byte("TOPSECRET "+testCard))
	if res.Status != StatusScanned || res.DetectedType != "text.utf8" || len(res.Findings) != 0 || res.SHA256 == "" {
		t.Errorf("%+v", res)
	}
}

func TestWorse(t *testing.T) {
	order := []string{StatusScanned, StatusTruncated, Unscannable(ReasonCorrupt), StatusTimeout}
	for i := range order {
		for j := range order {
			want := order[max(i, j)]
			if got := worse(order[i], order[j]); got != want {
				t.Errorf("worse(%s, %s) = %s", order[i], order[j], got)
			}
		}
	}
	if !IsUnscannable(Unscannable(ReasonEncrypted)) || IsUnscannable(StatusScanned) || IsUnscannable("unscannable:") {
		t.Error("IsUnscannable")
	}
}

func TestLimitsFrom(t *testing.T) {
	l := LimitsFrom(policy.FilesModule{MaxFileBytes: 1000, MaxTextBytes: 10, ScanTimeoutMs: 250})
	if l.MaxFileBytes != 1000 || l.MaxTextBytes != 10 || l.Timeout != 250*time.Millisecond || l.MaxArchiveBytes != 4000 ||
		l.MaxDepth != DefaultMaxDepth || l.MaxEntries != DefaultMaxEntries || l.MaxRatio != DefaultMaxRatio {
		t.Errorf("%+v", l)
	}
}
