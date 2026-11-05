package filescan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Legacy Office formats inside OLE compound files: Word 97–2003 (.doc),
// Excel 97–2003 (.xls, BIFF8) and PowerPoint 97–2003 (.ppt), plus the OLE
// "package" wrapper Office puts around embedded files. Only text is read;
// layout, formatting and macros are ignored.

// errPassword marks a document its own format says is encrypted.
var errPassword = errors.New("password protected")

// scanCFB scans an OLE compound file.
func (st *scanState) scanCFB(ra io.ReaderAt, size int64, depth int, name string) docResult {
	f, err := openCFB(ra, size, st.s.limits.MaxFileBytes)
	if err != nil {
		return st.scanCFBMarkers(ra, size) // not parseable: fall back to the stream names
	}
	top := f.top()
	if _, ok := top["EncryptedPackage"]; ok {
		if f.hasNameContaining("DRMEncrypted") {
			return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonRightsProtected)}
		}
		return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonPasswordProtected)}
	}
	var typ string
	var extract func(*cfbFile, map[string]cfbEntry, *textSink) error
	switch {
	case has(top, "WordDocument"):
		typ, extract = "ole.doc", extractDoc
	case has(top, "Workbook"):
		typ, extract = "ole.xls", extractXLS
	case has(top, "PowerPoint Document"):
		typ, extract = "ole.ppt", extractPPT
	case has(top, "Package"), has(top, "\x01Ole10Native"):
		return st.scanOLEPackage(f, top, depth, name)
	case has(top, "Book"):
		typ, extract = "ole.xls5", extractXLS5 // Excel 5/95
	case isMSG(top):
		return st.scanMSG(f, 0, depth, name)
	default:
		return docResult{typ: "ole", status: Unscannable(ReasonUnsupportedType)} // .vsd, …
	}
	sink := newSink(st)
	err = extract(f, top, sink)
	switch {
	case errors.Is(err, errPassword):
		return docResult{typ: typ, status: Unscannable(ReasonPasswordProtected)}
	case errors.Is(err, errCFB):
		err = errCorrupt
	}
	return st.finishDoc(typ, sink, err)
}

func has(m map[string]cfbEntry, name string) bool { _, ok := m[name]; return ok }

// hasNameContaining reports whether any entry's name contains s.
func (f *cfbFile) hasNameContaining(s string) bool {
	for _, e := range f.entries {
		if e.typ != 0 && strings.Contains(e.name, s) {
			return true
		}
	}
	return false
}

// scanCFBMarkers is the fallback for compound files that don't parse: an
// encrypted Office file is still recognised by its stream names.
func (st *scanState) scanCFBMarkers(ra io.ReaderAt, size int64) docResult {
	enc, drm, err := cfbMarkers(st, ra, size)
	switch {
	case err != nil:
		return docResult{typ: "ole", status: statusFor(st.ctx, err)}
	case enc && drm:
		return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonRightsProtected)}
	case enc:
		return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonPasswordProtected)}
	default:
		return docResult{typ: "ole", status: Unscannable(ReasonCorrupt)}
	}
}

// --- Word (.doc) ---

// extractDoc reads the text of a Word 97–2003 document through its piece
// table (the Clx in the table stream).
func extractDoc(f *cfbFile, top map[string]cfbEntry, sink *textSink) error {
	wd, err := f.read(top["WordDocument"])
	if err != nil {
		return err
	}
	le := binary.LittleEndian
	if len(wd) < 0x22 || le.Uint16(wd) != 0xA5EC {
		return errCFB
	}
	flags := le.Uint16(wd[0x0A:])
	if flags&0x0100 != 0 { // fEncrypted
		return errPassword
	}
	table := "0Table"
	if flags&0x0200 != 0 { // fWhichTblStm
		table = "1Table"
	}
	// FibRgFcLcb follows FibBase (32 bytes), csw, fibRgW, cslw, fibRgLw and
	// cbRgFcLcb; fcClx/lcbClx is its 34th pair.
	off := 32
	csw := int(le.Uint16(wd[off:]))
	off += 2 + csw*2
	if off+2 > len(wd) {
		return errCFB
	}
	cslw := int(le.Uint16(wd[off:]))
	off += 2 + cslw*4 + 2
	if off+34*8 > len(wd) {
		return errCFB
	}
	fcClx, lcbClx := le.Uint32(wd[off+33*8:]), le.Uint32(wd[off+33*8+4:])
	e, ok := top[table]
	if !ok {
		return errCFB
	}
	tbl, err := f.read(e)
	if err != nil {
		return err
	}
	if uint64(fcClx)+uint64(lcbClx) > uint64(len(tbl)) || lcbClx == 0 {
		return errCFB
	}
	clx := tbl[fcClx : fcClx+lcbClx]
	// Skip Prc entries (0x01) up to the Pcdt (0x02).
	for len(clx) > 0 && clx[0] == 0x01 {
		if len(clx) < 3 {
			return errCFB
		}
		n := int(int16(le.Uint16(clx[1:]))) // #nosec G115 -- cbGrpprl is a signed 16-bit length
		if n < 0 || 3+n > len(clx) {
			return errCFB
		}
		clx = clx[3+n:]
	}
	if len(clx) < 5 || clx[0] != 0x02 {
		return errCFB
	}
	plc := clx[5:]
	if lcb := le.Uint32(clx[1:]); uint64(lcb) <= uint64(len(plc)) {
		plc = plc[:lcb]
	}
	// PlcPcd: n+1 CPs (4 bytes each), then n 8-byte PCDs.
	if len(plc) < 4 || (len(plc)-4)%12 != 0 {
		return errCFB
	}
	n := (len(plc) - 4) / 12
	w := &docTextWriter{sink: sink}
	for i := 0; i < n; i++ {
		cpStart, cpEnd := le.Uint32(plc[4*i:]), le.Uint32(plc[4*(i+1):])
		if cpEnd < cpStart {
			return errCFB
		}
		chars := int64(cpEnd - cpStart)
		pcd := plc[4*(n+1)+8*i:]
		fc := le.Uint32(pcd[2:])
		var text string
		if fc&0x40000000 != 0 { // compressed: 8-bit, at fc/2
			start := int64(fc&0x3FFFFFFF) / 2
			if start+chars > int64(len(wd)) {
				return errCFB
			}
			text = decodeCP1252(wd[start : start+chars])
		} else {
			start := int64(fc)
			if start+2*chars > int64(len(wd)) {
				return errCFB
			}
			text = decodeUTF16LE(wd[start : start+2*chars])
		}
		if err := w.write(text); err != nil {
			return err
		}
	}
	return w.flush()
}

// docTextWriter turns Word's special characters into plain text: paragraph
// and cell marks become breaks, and field codes (between 0x13 and 0x14) are
// dropped like Word's instrText, keeping the field's result.
type docTextWriter struct {
	sink  *textSink
	sb    strings.Builder
	field int // nesting inside field codes
}

func (w *docTextWriter) write(s string) error {
	for _, r := range s {
		switch r {
		case 0x13:
			w.field++
		case 0x14, 0x15:
			if w.field > 0 {
				w.field--
			}
		case 0x0D, 0x0B, 0x0C:
			if w.field == 0 {
				w.sb.WriteByte('\n')
			}
		case 0x07:
			if w.field == 0 {
				w.sb.WriteByte('\t')
			}
		default:
			if w.field == 0 && (r >= 0x20 || r == '\t') {
				w.sb.WriteRune(r)
			}
		}
		if w.sb.Len() >= textReadBytes {
			if err := w.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *docTextWriter) flush() error {
	if w.sb.Len() == 0 {
		return nil
	}
	err := w.sink.WriteString(w.sb.String())
	w.sb.Reset()
	return err
}

func decodeCP1252(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(cp1252(c))
	}
	return sb.String()
}

func decodeUTF16LE(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(units))
}

// --- Excel (.xls, BIFF8) ---

// BIFF8 record types read for text.
const (
	xlsFilePass = 0x002F
	xlsSST      = 0x00FC
	xlsContinue = 0x003C
	xlsLabel    = 0x0204
	xlsNumber   = 0x0203
	xlsRK       = 0x027E
	xlsMulRK    = 0x00BD
	xlsFormula  = 0x0006
	xlsString   = 0x0207
	xlsRString  = 0x00D6 // BIFF5: a text cell with formatting runs
)

type biffRecord struct {
	typ  uint16
	data []byte
}

// biffRecords splits a BIFF stream into records.
func biffRecords(b []byte) []biffRecord {
	var out []biffRecord
	for off := 0; off+4 <= len(b); {
		typ, n := binary.LittleEndian.Uint16(b[off:]), int(binary.LittleEndian.Uint16(b[off+2:]))
		off += 4
		if off+n > len(b) {
			break
		}
		out = append(out, biffRecord{typ, b[off : off+n]})
		off += n
	}
	return out
}

// extractXLS reads an Excel 97–2003 workbook's shared strings (every text
// cell's text), its inline text cells and its number and formula values.
func extractXLS(f *cfbFile, top map[string]cfbEntry, sink *textSink) error {
	wb, err := f.read(top["Workbook"])
	if err != nil {
		return err
	}
	return extractBIFF(wb, readXLString, sink)
}

// extractXLS5 reads an Excel 5/95 workbook (BIFF5, the "Book" stream): the
// same records as BIFF8 with 8-bit strings, RSTRING cells and no shared
// string table.
func extractXLS5(f *cfbFile, top map[string]cfbEntry, sink *textSink) error {
	wb, err := f.read(top["Book"])
	if err != nil {
		return err
	}
	return extractBIFF(wb, readBIFF5String, sink)
}

// readBIFF5String reads a BIFF5 string: a 2-byte length, then 8-bit
// characters (the workbook's code page; read as Windows-1252).
func readBIFF5String(b []byte) (string, int, bool) {
	if len(b) < 2 {
		return "", 0, false
	}
	n := int(binary.LittleEndian.Uint16(b))
	if 2+n > len(b) {
		return "", 0, false
	}
	return decodeCP1252(b[2 : 2+n]), 2 + n, true
}

// extractBIFF reads the text and numbers of a BIFF stream; readString reads
// the version's inline strings.
func extractBIFF(wb []byte, readString func([]byte) (string, int, bool), sink *textSink) error {
	recs := biffRecords(wb)
	var sb strings.Builder
	flush := func() error {
		if sb.Len() == 0 {
			return nil
		}
		err := sink.WriteString(sb.String())
		sb.Reset()
		return err
	}
	cell := func(s string) error {
		sb.WriteString(s)
		sb.WriteByte('\t')
		if sb.Len() >= textReadBytes {
			return flush()
		}
		return nil
	}
	for i := 0; i < len(recs); i++ {
		r := recs[i]
		switch r.typ {
		case xlsFilePass:
			return errPassword
		case xlsSST:
			parts := [][]byte{r.data}
			for i+1 < len(recs) && recs[i+1].typ == xlsContinue {
				i++
				parts = append(parts, recs[i].data)
			}
			if err := readSST(parts, func(s string) error { sb.WriteString(s); sb.WriteByte('\n'); return flush() }); err != nil {
				return err
			}
		case xlsLabel, xlsRString:
			if len(r.data) > 6 {
				if s, _, ok := readString(r.data[6:]); ok {
					if err := cell(s); err != nil {
						return err
					}
				}
			}
		case xlsString:
			if s, _, ok := readString(r.data); ok {
				if err := cell(s); err != nil {
					return err
				}
			}
		case xlsNumber:
			if len(r.data) >= 14 {
				if err := cell(formatNumber(math.Float64frombits(binary.LittleEndian.Uint64(r.data[6:])))); err != nil {
					return err
				}
			}
		case xlsFormula:
			// A cached number, unless the last two bytes are 0xFFFF (then
			// it's a string, a bool or an error; strings follow as STRING).
			if len(r.data) >= 14 && binary.LittleEndian.Uint16(r.data[12:]) != 0xFFFF {
				if err := cell(formatNumber(math.Float64frombits(binary.LittleEndian.Uint64(r.data[6:])))); err != nil {
					return err
				}
			}
		case xlsRK:
			if len(r.data) >= 10 {
				if err := cell(formatNumber(rkValue(binary.LittleEndian.Uint32(r.data[6:])))); err != nil {
					return err
				}
			}
		case xlsMulRK:
			for off := 4; off+6 <= len(r.data)-2; off += 6 {
				if err := cell(formatNumber(rkValue(binary.LittleEndian.Uint32(r.data[off+2:])))); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

// formatNumber writes a cell value as text: whole numbers without a decimal
// point (so a card or account number reads as digits).
func formatNumber(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return ""
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e17 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// rkValue decodes an RK number.
func rkValue(rk uint32) float64 {
	var v float64
	if rk&0x02 != 0 {
		v = float64(int32(rk) >> 2) // #nosec G115 -- RK integers are signed 30-bit values
	} else {
		v = math.Float64frombits(uint64(rk&0xFFFFFFFC) << 32)
	}
	if rk&0x01 != 0 {
		v /= 100
	}
	return v
}

// readXLString reads an XLUnicodeString (cch, flags, characters) and
// returns it with the bytes it used.
func readXLString(b []byte) (string, int, bool) {
	if len(b) < 3 {
		return "", 0, false
	}
	cch := int(binary.LittleEndian.Uint16(b))
	flags := b[2]
	off := 3
	if flags&0x01 != 0 {
		if off+2*cch > len(b) {
			return "", 0, false
		}
		return decodeUTF16LE(b[off : off+2*cch]), off + 2*cch, true
	}
	if off+cch > len(b) {
		return "", 0, false
	}
	return decodeCP1252(b[off : off+cch]), off + cch, true
}

// readSST reads the shared string table, whose strings may continue across
// CONTINUE records: at a break the characters resume after a new flags byte
// that says whether they are 8- or 16-bit.
func readSST(parts [][]byte, emit func(string) error) error {
	if len(parts[0]) < 8 {
		return nil
	}
	count := binary.LittleEndian.Uint32(parts[0][4:])
	r := &sstReader{parts: parts, off: 8}
	for i := uint32(0); i < count; i++ {
		s, ok := r.string()
		if !ok {
			return nil // truncated table: keep what was read
		}
		if err := emit(s); err != nil {
			return err
		}
	}
	return nil
}

type sstReader struct {
	parts [][]byte
	p     int
	off   int
}

func (r *sstReader) avail() int {
	for r.p < len(r.parts) && r.off >= len(r.parts[r.p]) {
		r.p++
		r.off = 0
	}
	if r.p >= len(r.parts) {
		return 0
	}
	return len(r.parts[r.p]) - r.off
}

func (r *sstReader) bytes(n int) ([]byte, bool) {
	var out []byte
	for n > 0 {
		a := r.avail()
		if a == 0 {
			return nil, false
		}
		k := min(a, n)
		out = append(out, r.parts[r.p][r.off:r.off+k]...)
		r.off += k
		n -= k
	}
	return out, true
}

func (r *sstReader) string() (string, bool) {
	hdr, ok := r.bytes(3)
	if !ok {
		return "", false
	}
	cch := int(binary.LittleEndian.Uint16(hdr))
	flags := hdr[2]
	var runs, ext int
	if flags&0x08 != 0 {
		b, ok := r.bytes(2)
		if !ok {
			return "", false
		}
		runs = int(binary.LittleEndian.Uint16(b))
	}
	if flags&0x04 != 0 {
		b, ok := r.bytes(4)
		if !ok {
			return "", false
		}
		ext = int(int32(binary.LittleEndian.Uint32(b))) // #nosec G115 -- cbExtRst is a signed 32-bit length
		if ext < 0 {
			return "", false
		}
	}
	wide := flags&0x01 != 0
	var sb strings.Builder
	for cch > 0 {
		p0 := r.p
		a := r.avail()
		if a == 0 {
			return "", false
		}
		if r.p != p0 {
			// The characters continue in a CONTINUE record, which starts
			// with its own flags byte (8- or 16-bit from here on).
			wide = r.parts[r.p][r.off]&0x01 != 0
			r.off++
			if a = r.avail(); a == 0 {
				return "", false
			}
		}
		width := 1
		if wide {
			width = 2
		}
		n := min(cch, a/width)
		if n == 0 {
			return "", false
		}
		b := r.parts[r.p][r.off : r.off+n*width]
		r.off += n * width
		if wide {
			sb.WriteString(decodeUTF16LE(b))
		} else {
			sb.WriteString(decodeCP1252(b))
		}
		cch -= n
	}
	_, _ = r.bytes(4*runs + ext) // formatting runs and phonetic data: not text
	return sb.String(), true
}

// --- PowerPoint (.ppt) ---

const (
	pptTextChars   = 0x0FA0
	pptTextBytes   = 0x0FA8
	pptCryptSess10 = 0x2F14
)

// extractPPT reads the text atoms of a PowerPoint 97–2003 presentation. The
// record tree is walked flat: a container's header is stepped over and its
// children read in place.
func extractPPT(f *cfbFile, top map[string]cfbEntry, sink *textSink) error {
	if has(top, "EncryptedSummary") {
		return errPassword
	}
	doc, err := f.read(top["PowerPoint Document"])
	if err != nil {
		return err
	}
	var sb strings.Builder
	le := binary.LittleEndian
	for off := 0; off+8 <= len(doc); {
		verInst, typ, n := le.Uint16(doc[off:]), le.Uint16(doc[off+2:]), int64(le.Uint32(doc[off+4:]))
		off += 8
		if typ == pptCryptSess10 {
			return errPassword
		}
		if verInst&0x0F == 0x0F {
			continue // container: its children follow
		}
		if int64(off)+n > int64(len(doc)) {
			break
		}
		body := doc[off : off+int(n)]
		off += int(n)
		switch typ {
		case pptTextChars:
			sb.WriteString(decodeUTF16LE(body))
		case pptTextBytes:
			sb.WriteString(decodeCP1252(body))
		default:
			continue
		}
		sb.WriteByte('\n')
		if sb.Len() >= textReadBytes {
			if err := sink.WriteString(sb.String()); err != nil {
				return err
			}
			sb.Reset()
		}
	}
	if sb.Len() > 0 {
		return sink.WriteString(strings.ReplaceAll(sb.String(), "\r", "\n"))
	}
	return nil
}

// --- Embedded OLE packages ---

// scanOLEPackage scans the file an OLE package object wraps: the "Package"
// stream is the file itself; "\x01Ole10Native" holds a label, paths and the
// file's bytes.
func (st *scanState) scanOLEPackage(f *cfbFile, top map[string]cfbEntry, depth int, name string) docResult {
	if depth >= st.s.limits.MaxDepth {
		return docResult{typ: "ole.package", status: Unscannable(ReasonTooLarge)}
	}
	var data []byte
	var err error
	if e, ok := top["Package"]; ok {
		data, err = f.read(e)
	} else {
		var raw []byte
		if raw, err = f.read(top["\x01Ole10Native"]); err == nil {
			data, err = ole10NativeData(raw)
		}
	}
	if err != nil {
		return docResult{typ: "ole.package", status: st.entryStatus(err)}
	}
	doc := st.scanDoc(bytes.NewReader(data), int64(len(data)), depth+1, name)
	if doc.typ != "" {
		doc.typ = "ole.package/" + doc.typ
	}
	return doc
}

// ole10NativeData extracts the file from an Ole10Native stream: total size,
// a 2-byte type, label and source path (NUL-terminated), 4 reserved bytes,
// a length-prefixed temp path, then the length-prefixed data.
func ole10NativeData(b []byte) ([]byte, error) {
	le := binary.LittleEndian
	off := 4 + 2
	for k := 0; k < 2; k++ { // label, source path
		i := bytes.IndexByte(b[min(off, len(b)):], 0)
		if i < 0 {
			return nil, errCFB
		}
		off += i + 1
	}
	off += 4
	if off+4 > len(b) {
		return nil, errCFB
	}
	n := int(le.Uint32(b[off:]))
	off += 4
	if n < 0 || off+n+4 > len(b) {
		return nil, errCFB
	}
	off += n
	size := int(le.Uint32(b[off:]))
	off += 4
	if size < 0 || off+size > len(b) {
		return nil, errCFB
	}
	return b[off : off+size], nil
}
