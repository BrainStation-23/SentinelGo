package filescan

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"unicode/utf16"
)

// buildCFB writes a version 3 compound file (512-byte sectors) with the
// given top-level streams, in order. Streams under 4096 bytes go in the mini
// stream, as real files do, so both read paths are exercised.
func buildCFB(t testing.TB, streams ...[2]string) []byte {
	t.Helper()
	const sec, mini, cutoff = 512, 64, 4096
	le := binary.LittleEndian
	type big struct {
		data  []byte
		start uint32
	}
	var miniData []byte
	var miniFAT []uint32
	starts := make([]uint32, len(streams))
	var bigs []big
	for i, s := range streams {
		d := []byte(s[1])
		if len(d) < cutoff {
			starts[i] = uint32(len(miniData) / mini)
			n := (len(d) + mini - 1) / mini
			for k := 0; k < n; k++ {
				next := uint32(len(miniFAT) + 1)
				if k == n-1 {
					next = cfbEndOfChain
				}
				miniFAT = append(miniFAT, next)
			}
			if n == 0 {
				starts[i] = cfbEndOfChain
			}
			miniData = append(miniData, d...)
			miniData = append(miniData, make([]byte, n*mini-len(d))...)
		} else {
			bigs = append(bigs, big{data: d})
			starts[i] = uint32(len(bigs) - 1) // fixed up below
		}
	}
	// Names with "/" live in storages, created from the paths.
	var storages []string
	seenStorage := map[string]bool{}
	for _, st := range streams {
		parts := strings.Split(st[0], "/")
		for k := 1; k < len(parts); k++ {
			p := strings.Join(parts[:k], "/")
			if !seenStorage[p] {
				seenStorage[p] = true
				storages = append(storages, p)
			}
		}
	}
	nDir := (1 + len(storages) + len(streams) + 3) / 4
	sectorsOf := func(n int) int { return (n + sec - 1) / sec }
	nMiniFAT := sectorsOf(len(miniFAT) * 4)
	nMiniStream := sectorsOf(len(miniData))
	nBig := 0
	for _, b := range bigs {
		nBig += sectorsOf(len(b.data))
	}
	nData := nDir + nMiniFAT + nMiniStream + nBig
	nFAT := 1
	for (nFAT+nData)*4 > nFAT*sec {
		nFAT++
	}
	fat := make([]uint32, nFAT*sec/4)
	for i := range fat {
		fat[i] = cfbFree
	}
	next := uint32(0)
	for i := 0; i < nFAT; i++ {
		fat[next] = 0xFFFFFFFD
		next++
	}
	alloc := func(n int) uint32 {
		if n == 0 {
			return cfbEndOfChain
		}
		start := next
		for k := 0; k < n; k++ {
			if k == n-1 {
				fat[next] = cfbEndOfChain
			} else {
				fat[next] = next + 1
			}
			next++
		}
		return start
	}
	dirStart := alloc(nDir)
	miniFATStart := alloc(nMiniFAT)
	miniStreamStart := alloc(nMiniStream)
	for i := range bigs {
		bigs[i].start = alloc(sectorsOf(len(bigs[i].data)))
	}
	bi := 0
	for i, s := range streams {
		if len(s[1]) >= cutoff {
			starts[i] = bigs[bi].start
			bi++
		}
	}

	entry := func(name string, typ byte, child, right, start uint32, size uint64) []byte {
		b := make([]byte, cfbDirEntry)
		units := utf16.Encode([]rune(name))
		for i, u := range units {
			le.PutUint16(b[2*i:], u)
		}
		le.PutUint16(b[0x40:], uint16(2*len(units)+2))
		b[0x42], b[0x43] = typ, 1
		le.PutUint32(b[0x44:], cfbNoStream)
		le.PutUint32(b[0x48:], right)
		le.PutUint32(b[0x4C:], child)
		le.PutUint32(b[0x74:], start)
		le.PutUint64(b[0x78:], size)
		return b
	}
	// Directory: the root, the storages, then the streams. Each storage's
	// children are chained through their right siblings.
	type dnode struct {
		name     string
		typ      byte
		start    uint32
		size     uint64
		children []int
	}
	nodes := []dnode{{name: "Root Entry", typ: cfbTypeRoot, start: miniStreamStart, size: uint64(len(miniData))}}
	index := map[string]int{"": 0}
	parentOf := func(p string) int {
		if i := strings.LastIndex(p, "/"); i >= 0 {
			return index[p[:i]]
		}
		return 0
	}
	baseOf := func(p string) string { return p[strings.LastIndex(p, "/")+1:] }
	for _, st := range storages {
		index[st] = len(nodes)
		nodes[parentOf(st)].children = append(nodes[parentOf(st)].children, len(nodes))
		nodes = append(nodes, dnode{name: baseOf(st), typ: cfbTypeStorage, start: cfbEndOfChain})
	}
	for i, st := range streams {
		nodes[parentOf(st[0])].children = append(nodes[parentOf(st[0])].children, len(nodes))
		nodes = append(nodes, dnode{name: baseOf(st[0]), typ: cfbTypeStream, start: starts[i], size: uint64(len(st[1]))})
	}
	right := make([]uint32, len(nodes))
	for i := range right {
		right[i] = cfbNoStream
	}
	var dir []byte
	for _, n := range nodes {
		for k := 0; k+1 < len(n.children); k++ {
			right[n.children[k]] = uint32(n.children[k+1])
		}
	}
	for i, n := range nodes {
		child := uint32(cfbNoStream)
		if len(n.children) > 0 {
			child = uint32(n.children[0])
		}
		dir = append(dir, entry(n.name, n.typ, child, right[i], n.start, n.size)...)
	}
	pad := func(b []byte) []byte { return append(b, make([]byte, (sec-len(b)%sec)%sec)...) }

	hdr := make([]byte, sec)
	copy(hdr, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
	le.PutUint16(hdr[0x18:], 0x3E)
	le.PutUint16(hdr[0x1A:], 3)
	le.PutUint16(hdr[0x1C:], 0xFFFE)
	le.PutUint16(hdr[0x1E:], 9)
	le.PutUint16(hdr[0x20:], 6)
	le.PutUint32(hdr[0x2C:], uint32(nFAT))
	le.PutUint32(hdr[0x30:], dirStart)
	le.PutUint32(hdr[0x38:], cutoff)
	le.PutUint32(hdr[0x3C:], miniFATStart)
	le.PutUint32(hdr[0x40:], uint32(nMiniFAT))
	le.PutUint32(hdr[0x44:], cfbEndOfChain)
	for i := 0; i < 109; i++ {
		v := uint32(cfbFree)
		if i < nFAT {
			v = uint32(i)
		}
		le.PutUint32(hdr[0x4C+4*i:], v)
	}
	out := append([]byte(nil), hdr...)
	fatBytes := make([]byte, len(fat)*4)
	for i, v := range fat {
		le.PutUint32(fatBytes[4*i:], v)
	}
	out = append(out, fatBytes...)
	out = append(out, pad(dir)...)
	mf := make([]byte, len(miniFAT)*4)
	for i, v := range miniFAT {
		le.PutUint32(mf[4*i:], v)
	}
	out = append(out, pad(mf)...)
	out = append(out, pad(miniData)...)
	for _, b := range bigs {
		out = append(out, pad(b.data)...)
	}
	return out
}

// wordDoc builds a .doc's WordDocument and 1Table streams with text in one
// compressed (8-bit) piece and one UTF-16 piece.
func wordDoc(text8, text16 string, flags uint16) [][2]string {
	le := binary.LittleEndian
	wd := make([]byte, 2048)
	le.PutUint16(wd, 0xA5EC)
	le.PutUint16(wd[0x0A:], 0x0200|flags) // fWhichTblStm: 1Table
	off := 32
	le.PutUint16(wd[off:], 14)
	off += 2 + 28
	le.PutUint16(wd[off:], 22)
	off += 2 + 88
	le.PutUint16(wd[off:], 93)
	off += 2
	clxAt := off + 33*8
	// Text: 8-bit at 1024, UTF-16 at 1536.
	copy(wd[1024:], text8)
	u := utf16.Encode([]rune(text16))
	for i, v := range u {
		le.PutUint16(wd[1536+2*i:], v)
	}
	// Clx: one Prc to skip, then the Pcdt.
	var plc []byte
	cp := []uint32{0, uint32(len(text8)), uint32(len(text8) + len(u))}
	for _, c := range cp {
		plc = le.AppendUint32(plc, c)
	}
	pcd := func(fc uint32) []byte {
		b := make([]byte, 8)
		le.PutUint32(b[2:], fc)
		return b
	}
	plc = append(plc, pcd(1024*2|0x40000000)...)
	plc = append(plc, pcd(1536)...)
	clx := []byte{0x01, 2, 0, 0xAA, 0xBB, 0x02}
	clx = le.AppendUint32(clx, uint32(len(plc)))
	clx = append(clx, plc...)
	table := make([]byte, 100)
	table = append(table, clx...)
	le.PutUint32(wd[clxAt:], 100)
	le.PutUint32(wd[clxAt+4:], uint32(len(clx)))
	return [][2]string{{"WordDocument", string(wd)}, {"1Table", string(table)}}
}

func biff(typ uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, typ)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func xlString(s string, wide bool) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len([]rune(s))))
	if wide {
		b = append(b, 1)
		for _, u := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
		return b
	}
	return append(append(b, 0), s...)
}

// workbook builds a BIFF8 Workbook stream: a shared string table whose last
// string continues (as 16-bit) in a CONTINUE record, a NUMBER, an RK, a
// MULRK and a cached formula value.
func workbook(extra ...[]byte) string {
	le := binary.LittleEndian
	sst := le.AppendUint32(nil, 3)
	sst = le.AppendUint32(sst, 3)
	sst = append(sst, xlString("customer", false)...)
	sst = append(sst, xlString("TOPSECRET", true)...)
	// "split TOPSECRET" begins 8-bit, continues 16-bit after the break.
	sst = le.AppendUint16(sst, uint16(len("split TOPSECRET")))
	sst = append(sst, 0)
	sst = append(sst, "split TOP"...)
	cont := []byte{1}
	for _, u := range utf16.Encode([]rune("SECRET")) {
		cont = le.AppendUint16(cont, u)
	}
	num := make([]byte, 14)
	le.PutUint64(num[6:], math.Float64bits(4111111111111111))
	rk := make([]byte, 10)
	le.PutUint32(rk[6:], uint32(1234567)<<2|0x02)
	mulrk := make([]byte, 4)
	for _, v := range []int32{11, 22} {
		mulrk = le.AppendUint16(mulrk, 0)
		mulrk = le.AppendUint32(mulrk, uint32(v)<<2|0x02)
	}
	mulrk = le.AppendUint16(mulrk, 2)
	formula := make([]byte, 20)
	le.PutUint64(formula[6:], math.Float64bits(5555.5))
	var b []byte
	b = append(b, biff(0x0809, make([]byte, 16))...)
	for _, e := range extra {
		b = append(b, e...)
	}
	b = append(b, biff(xlsSST, sst)...)
	b = append(b, biff(xlsContinue, cont)...)
	b = append(b, biff(xlsNumber, num)...)
	b = append(b, biff(xlsRK, rk)...)
	b = append(b, biff(xlsMulRK, mulrk)...)
	b = append(b, biff(xlsFormula, formula)...)
	b = append(b, biff(xlsLabel, append(make([]byte, 6), xlString("label TOPSECRET", false)...))...)
	return string(b)
}

func pptRecord(verInst, typ uint16, body []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, verInst)
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

func powerPoint(extra ...[]byte) string {
	var u16 []byte
	for _, u := range utf16.Encode([]rune("Slide TOPSECRET")) {
		u16 = binary.LittleEndian.AppendUint16(u16, u)
	}
	children := pptRecord(0, pptTextChars, u16)
	children = append(children, pptRecord(0, pptTextBytes, []byte("card "+testCard))...)
	children = append(children, pptRecord(0, 0x0FA1, []byte{1, 2, 3, 4})...) // a non-text atom
	for _, e := range extra {
		children = append(children, e...)
	}
	return string(pptRecord(0x000F, 0x03E8, children))
}

// ole10Native wraps data the way an embedded OLE package stores it.
func ole10Native(label string, data []byte) string {
	le := binary.LittleEndian
	var b []byte
	b = le.AppendUint32(b, 0) // total size: not checked
	b = le.AppendUint16(b, 2)
	b = append(b, label+"\x00C:\\src\\"+label+"\x00"...)
	b = le.AppendUint32(b, 0x00030000)
	tmp := "C:\\tmp\\" + label + "\x00"
	b = le.AppendUint32(b, uint32(len(tmp)))
	b = append(b, tmp...)
	b = le.AppendUint32(b, uint32(len(data)))
	b = append(b, data...)
	return string(b)
}

func TestScan_LegacyOffice(t *testing.T) {
	s := newTestScanner(t)
	bigPad := strings.Repeat("x", 5000) // forces a regular (non-mini) stream
	for _, tc := range []struct {
		name, typ, status string
		data              []byte
		cards, keywords   int
	}{
		{"doc", "ole.doc", StatusScanned, buildCFB(t, wordDoc("Card "+testCard+"\r\x13 FIELD TOPSECRET \x14result\x15\r", "Müller TOPSECRET\x07", 0)...), 1, 1},
		{"doc encrypted", "ole.doc", Unscannable(ReasonPasswordProtected), buildCFB(t, wordDoc("x", "y", 0x0100)...), 0, 0},
		{"xls", "ole.xls", StatusScanned, buildCFB(t, [2]string{"Workbook", workbook()}), 1, 3}, // the card is a number cell
		{"xls encrypted", "ole.xls", Unscannable(ReasonPasswordProtected), buildCFB(t, [2]string{"Workbook", workbook(biff(xlsFilePass, make([]byte, 6)))}), 0, 0},
		{"xls in a big stream", "ole.xls", StatusScanned, buildCFB(t, [2]string{"Workbook", workbook(biff(0x0012, []byte(bigPad[:4000])), biff(0x0012, []byte(bigPad[:1000])))}), 1, 3},
		{"ppt", "ole.ppt", StatusScanned, buildCFB(t, [2]string{"PowerPoint Document", powerPoint()}), 1, 1},
		{"ppt encrypted", "ole.ppt", Unscannable(ReasonPasswordProtected), buildCFB(t, [2]string{"PowerPoint Document", powerPoint(pptRecord(0x000F, pptCryptSess10, nil))}), 0, 0},
		{"encrypted ooxml", "ooxml.encrypted", Unscannable(ReasonPasswordProtected), buildCFB(t, [2]string{"EncryptionInfo", "x"}, [2]string{"EncryptedPackage", "y"}), 0, 0},
		{"rights managed ooxml", "ooxml.encrypted", Unscannable(ReasonRightsProtected), buildCFB(t, [2]string{"EncryptedPackage", "y"}, [2]string{"DRMEncryptedDataSpace", "z"}), 0, 0},
		{"excel 5, empty", "ole.xls5", StatusScanned, buildCFB(t, [2]string{"Book", "x"}), 0, 0},
		{"compound file of another kind", "ole", Unscannable(ReasonUnsupportedType), buildCFB(t, [2]string{"__properties_version1.0", "x"}), 0, 0},
		{"ole package", "ole.package/text.utf8", StatusScanned, buildCFB(t, [2]string{"\x01Ole10Native", ole10Native("keys.txt", []byte("TOPSECRET"))}), 0, 1},
		{"ole package stream", "ole.package/ooxml.docx", StatusScanned, buildCFB(t, [2]string{"Package", string(docx(t, `<w:p><w:r><w:t>`+testCard+`</w:t></w:r></w:p>`))}), 1, 0},
	} {
		res := scanBytes(t, s, tc.data)
		if res.Status != tc.status || res.DetectedType != tc.typ {
			t.Errorf("%s: status %q type %q", tc.name, res.Status, res.DetectedType)
			continue
		}
		if got := count(res.Findings, "pii.credit_card"); got != tc.cards {
			t.Errorf("%s: %d cards %+v", tc.name, got, res.Findings)
		}
		if got := count(res.Findings, "kw"); got != tc.keywords {
			t.Errorf("%s: %d keywords %+v", tc.name, got, res.Findings)
		}
	}
}

// The .doc's text comes out as Word shows it: field codes dropped, the
// field result kept, paragraph and cell marks as breaks.
func TestExtractDoc_Text(t *testing.T) {
	data := buildCFB(t, wordDoc("A\r\x13 HYPERLINK x \x14link\x15\rB", "Café\x07end", 0)...)
	f, err := openCFB(bytes.NewReader(data), int64(len(data)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	st := &scanState{s: &Scanner{chunk: 1 << 20, overlap: 4096}, ctx: t.Context(), textLeft: 1 << 20}
	sink := newSink(st)
	if err := extractDoc(f, f.top(), sink); err != nil {
		t.Fatal(err)
	}
	if got := string(sink.buf); got != "A\nlink\nBCafé\tend" {
		t.Errorf("text %q", got)
	}
}

func TestExtractXLS_Text(t *testing.T) {
	data := buildCFB(t, [2]string{"Workbook", workbook()})
	f, err := openCFB(bytes.NewReader(data), int64(len(data)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	st := &scanState{s: &Scanner{chunk: 1 << 20, overlap: 4096}, ctx: t.Context(), textLeft: 1 << 20}
	sink := newSink(st)
	if err := extractXLS(f, f.top(), sink); err != nil {
		t.Fatal(err)
	}
	got := string(sink.buf)
	for _, want := range []string{"customer\n", "TOPSECRET\n", "split TOPSECRET\n", "4111111111111111\t", "1234567\t", "11\t22\t", "5555.5\t", "label TOPSECRET\t"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

// Hostile compound files: loops and out-of-range sectors are corrupt, not
// hangs or panics.
func TestOpenCFB_Malformed(t *testing.T) {
	good := buildCFB(t, [2]string{"WordDocument", strings.Repeat("y", 5000)})
	le := binary.LittleEndian
	for name, mutate := range map[string]func(b []byte){
		"truncated":         func(b []byte) {},
		"bad sector shift":  func(b []byte) { le.PutUint16(b[0x1E:], 20) },
		"dir out of range":  func(b []byte) { le.PutUint32(b[0x30:], 1<<20) },
		"fat count too big": func(b []byte) { le.PutUint32(b[0x2C:], 1<<30) },
		"chain loop": func(b []byte) {
			// Point the directory's FAT entry at itself.
			dir := le.Uint32(b[0x30:])
			le.PutUint32(b[512+4*int(dir):], dir)
		},
	} {
		b := append([]byte(nil), good...)
		if name == "truncated" {
			b = b[:600]
		}
		mutate(b)
		if _, err := openCFB(bytes.NewReader(b), int64(len(b)), 1<<20); err == nil && name != "chain loop" {
			t.Errorf("%s: opened", name)
		}
		// Whatever opens, scanning must end cleanly.
		res := scanBytes(t, newTestScanner(t), b)
		if !IsUnscannable(res.Status) && res.Status != StatusScanned {
			t.Errorf("%s: status %q", name, res.Status)
		}
	}
	// A stream over the size limit isn't read.
	f, err := openCFB(bytes.NewReader(good), int64(len(good)), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(f.top()["WordDocument"]); err != errTooLarge {
		t.Errorf("oversized stream: %v", err)
	}
}

// Files embedded in Office documents are scanned as entries; ones that
// can't be read (an equation, a drawing) don't make the document
// unscannable, but a password-protected one does.
func TestScan_EmbeddedFiles(t *testing.T) {
	s := newTestScanner(t)
	inner := docx(t, `<w:p><w:r><w:t>TOPSECRET</w:t></w:r></w:p>`)
	equation := buildCFB(t, [2]string{"Equation Native", "x"})
	pkg := buildCFB(t, [2]string{"\x01Ole10Native", ole10Native("cards.csv", []byte(testCard))})
	outer := docx(t, `<w:p><w:r><w:t>cover</w:t></w:r></w:p>`,
		[2]string{"word/embeddings/Microsoft_Excel_Worksheet.docx", string(inner)},
		[2]string{"word/embeddings/oleObject1.bin", string(equation)},
		[2]string{"word/embeddings/oleObject2.bin", string(pkg)},
	)
	res := scanBytes(t, s, outer)
	if res.Status != StatusScanned || res.DetectedType != "ooxml.docx" {
		t.Fatalf("status %q type %q entries %+v", res.Status, res.DetectedType, res.Entries)
	}
	got := map[string]Entry{}
	for _, e := range res.Entries {
		got[e.Name] = e
	}
	if e := got["word/embeddings/Microsoft_Excel_Worksheet.docx"]; count(e.Findings, "kw") != 1 {
		t.Errorf("embedded docx: %+v", e)
	}
	if e := got["word/embeddings/oleObject2.bin"]; count(e.Findings, "pii.credit_card") != 1 || e.DetectedType != "ole.package/text.utf8" {
		t.Errorf("embedded package: %+v", e)
	}
	if _, ok := got["word/embeddings/oleObject1.bin"]; ok || len(res.Entries) != 2 {
		t.Errorf("an unreadable embedded object was recorded: %+v", res.Entries)
	}

	locked := docx(t, `<w:p/>`, [2]string{"word/embeddings/secret.docx", string(buildCFB(t, [2]string{"EncryptedPackage", "x"}))})
	if res := scanBytes(t, s, locked); res.Status != Unscannable(ReasonPasswordProtected) {
		t.Errorf("password-protected embedded file: %q", res.Status)
	}
}
