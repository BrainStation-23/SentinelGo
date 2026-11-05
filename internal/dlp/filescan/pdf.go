package filescan

// PDF text extraction (#327). It reads the file's objects in order (no
// cross-reference table needed, so damaged files still give their text),
// including objects packed in object streams, decodes Flate, ASCII85 and
// ASCIIHex streams within the archive budget, and pulls the text out of
// content streams' text operators. Fonts with a ToUnicode CMap are mapped
// to Unicode; strings in fonts without one are read as PDFDocEncoding.
//
// What it can't read is reported, never passed off as clean:
//   - an encrypted file is unscannable:encrypted;
//   - a file with no text operators at all (typically a scanned image; OCR
//     is out of scope) is unscannable:unsupported_type;
//   - text in a font without a ToUnicode map whose codes don't read as text
//     (glyph ids of an Identity-H font), or a stream it can't decode, makes
//     the result truncated.

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// pdfMaxObjects bounds how many objects one file may define.
const pdfMaxObjects = 200000

// pdfObj is one indirect object: its value, and for a stream the raw
// (still encoded) data.
type pdfObj struct {
	val    any
	stream []byte
	isStm  bool
}

type pdfDoc struct {
	objs      map[int]*pdfObj
	order     []int // stream objects in file order
	encrypted bool
}

var pdfObjRe = regexp.MustCompile(`(\d{1,10})\s+(\d{1,5})\s+obj\b`)

// scanPDF extracts and scans a PDF's text.
func (st *scanState) scanPDF(ra io.ReaderAt, size int64) docResult {
	data := make([]byte, size)
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		return docResult{typ: "pdf", status: statusFor(st.ctx, err)}
	}
	doc, err := st.parsePDF(data)
	if err != nil {
		return docResult{typ: "pdf", status: statusFor(st.ctx, err)}
	}
	if doc.encrypted {
		return docResult{typ: "pdf", status: Unscannable(ReasonEncrypted)}
	}
	sink := newSink(st)
	x := &pdfExtractor{st: st, doc: doc, sink: sink, cmaps: map[int]*pdfCMap{}}
	err = x.run()
	d := st.finishDoc("pdf", sink, err)
	switch {
	case err != nil:
	case x.textOps == 0:
		d.status = Unscannable(ReasonUnsupportedType)
	case x.unreadable:
		d.status = worse(d.status, StatusTruncated)
	}
	return d
}

// parsePDF indexes the file's objects.
func (st *scanState) parsePDF(data []byte) (*pdfDoc, error) {
	doc := &pdfDoc{objs: map[int]*pdfObj{}}
	pos := 0
	for pos < len(data) {
		if err := st.ctx.Err(); err != nil {
			return nil, err
		}
		loc := pdfObjRe.FindSubmatchIndex(data[pos:])
		if loc == nil {
			break
		}
		num := atoiBytes(data[pos+loc[2] : pos+loc[3]])
		l := &pdfLexer{b: data, p: pos + loc[1]}
		v, _ := l.value(0)
		obj := &pdfObj{val: v}
		end := l.p
		if d, ok := v.(pdfDict); ok {
			if t := l.next(); t.kind == tokKeyword && string(t.val) == "stream" {
				start := t.pos
				if start < len(data) && data[start] == '\r' {
					start++
				}
				if start < len(data) && data[start] == '\n' {
					start++
				}
				stop := streamEnd(data, start, d)
				obj.stream, obj.isStm = data[start:stop], true
				end = stop
			}
			if d.name("Type") == "XRef" && d["Encrypt"] != nil {
				doc.encrypted = true
			}
		}
		if _, dup := doc.objs[num]; !dup || obj.isStm {
			doc.objs[num] = obj // a later update of the same object wins
		}
		if obj.isStm {
			doc.order = append(doc.order, num)
		}
		if len(doc.objs) > pdfMaxObjects {
			return nil, errTooLarge
		}
		pos = max(end, pos+loc[1])
	}
	if pdfHasTrailerEncrypt(data) {
		doc.encrypted = true
	}
	if err := st.unpackObjStms(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// streamEnd finds the end of a stream's data: /Length when it is direct and
// is followed by endstream, else the next "endstream".
func streamEnd(data []byte, start int, d pdfDict) int {
	if n, ok := d["Length"].(float64); ok && n >= 0 && start+int(n) <= len(data) {
		rest := bytes.TrimLeft(data[start+int(n):min(len(data), start+int(n)+16)], "\r\n \t")
		if bytes.HasPrefix(rest, []byte("endstream")) {
			return start + int(n)
		}
	}
	i := bytes.Index(data[start:], []byte("endstream"))
	if i < 0 {
		return len(data)
	}
	return start + i
}

func pdfHasTrailerEncrypt(data []byte) bool {
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte("trailer"))
		if i < 0 {
			return false
		}
		l := &pdfLexer{b: data, p: off + i + len("trailer")}
		if d, ok := l.value(0); ok {
			if dd, ok := d.(pdfDict); ok && dd["Encrypt"] != nil {
				return true
			}
		}
		// continue after what was parsed, so text after many "trailer"
		// words is read once, not once per word
		off = max(off+i+len("trailer"), l.p)
	}
}

func atoiBytes(b []byte) int {
	n := 0
	for _, c := range b {
		n = n*10 + int(c-'0')
		if n > 1<<31 {
			return -1
		}
	}
	return n
}

// unpackObjStms reads the objects packed in object streams (PDF 1.5+);
// objects defined directly in the file win over packed ones.
func (st *scanState) unpackObjStms(doc *pdfDoc) error {
	for _, num := range doc.order {
		o := doc.objs[num]
		d, _ := o.val.(pdfDict)
		if d.name("Type") != "ObjStm" {
			continue
		}
		data, err := st.decodeStream(d, o.stream)
		if err != nil {
			if errors.Is(err, errUnsupported) || errors.Is(err, errCorrupt) {
				continue
			}
			return err
		}
		n, _ := d["N"].(float64)
		first, _ := d["First"].(float64)
		if n <= 0 || first < 0 || int(first) > len(data) {
			continue
		}
		type packed struct{ num, off int }
		var list []packed
		hdr := &pdfLexer{b: data[:int(first)]}
		for i := 0; i < int(n) && i < pdfMaxObjects; i++ {
			a, b := hdr.next(), hdr.next()
			if a.kind != tokNumber || b.kind != tokNumber {
				break
			}
			off := int(first) + int(b.num)
			if off < int(first) || off >= len(data) {
				continue
			}
			list = append(list, packed{int(a.num), off})
		}
		// each object ends where the next one starts, so a damaged object
		// can't make every later one re-read the rest of the stream
		sort.Slice(list, func(i, j int) bool { return list[i].off < list[j].off })
		for i, p := range list {
			if _, exists := doc.objs[p.num]; exists {
				continue
			}
			end := len(data)
			if i+1 < len(list) {
				end = list[i+1].off
			}
			l := &pdfLexer{b: data[:end], p: p.off}
			v, _ := l.value(0)
			doc.objs[p.num] = &pdfObj{val: v}
			if len(doc.objs) > pdfMaxObjects {
				return errTooLarge
			}
		}
	}
	return nil
}

// decodeStream applies a stream's filters within the archive budget.
// errUnsupported: a filter we don't implement (images, LZW, encryption);
// errTooLarge: the budget or the ratio limit was hit.
func (st *scanState) decodeStream(d pdfDict, raw []byte) ([]byte, error) {
	data := raw
	for _, f := range d.names("Filter") {
		var r io.Reader
		switch f {
		case "FlateDecode", "Fl":
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, errCorrupt
			}
			r = zr
		case "ASCII85Decode", "A85":
			src := data
			if i := bytes.Index(src, []byte("~>")); i >= 0 {
				src = src[:i]
			}
			r = ascii85.NewDecoder(bytes.NewReader(bytes.TrimPrefix(bytes.TrimSpace(src), []byte("<~"))))
		case "ASCIIHexDecode", "AHx":
			l := &pdfLexer{b: append(append([]byte{'<'}, data...), '>')}
			data = l.next().val
			continue
		default:
			return nil, errUnsupported
		}
		limit := min(st.archiveLeft, st.s.limits.MaxFileBytes, int64(len(data)+1)*st.s.limits.MaxRatio+64<<10)
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(ctxReader{st.ctx, r}, limit+1))
		st.archiveLeft -= min(n, limit)
		switch {
		case n > limit:
			return nil, errTooLarge
		case err != nil && st.ctx.Err() != nil:
			return nil, st.ctx.Err()
		case err != nil && !errors.Is(err, io.ErrUnexpectedEOF):
			if buf.Len() == 0 {
				return nil, errCorrupt
			}
			// a truncated Flate stream still gives what it decoded
		}
		data = buf.Bytes()
	}
	if p, ok := d["DecodeParms"].(pdfDict); ok {
		if pr, _ := p["Predictor"].(float64); pr > 1 {
			return nil, errUnsupported // only images and xref streams use predictors
		}
	}
	return data, nil
}

// pdfExtractor pulls the text out of a parsed PDF.
type pdfExtractor struct {
	st    *scanState
	doc   *pdfDoc
	sink  *textSink
	cmaps map[int]*pdfCMap // by font object

	fontsFor map[int]map[string]int // content stream object → font name → font object
	global   map[string]int         // font names from every resource dictionary

	textOps    int  // text-showing operators seen
	unreadable bool // some text or a content stream couldn't be read
}

func (x *pdfExtractor) resolve(v any) any {
	for i := 0; i < 8; i++ {
		r, ok := v.(pdfRef)
		if !ok {
			return v
		}
		o := x.doc.objs[int(r)]
		if o == nil {
			return nil
		}
		v = o.val
	}
	return nil
}

func (x *pdfExtractor) dict(v any) pdfDict {
	d, _ := x.resolve(v).(pdfDict)
	return d
}

// fontMap reads a resource dictionary's /Font entries.
func (x *pdfExtractor) fontMap(res pdfDict) map[string]int {
	fonts := x.dict(res["Font"])
	if fonts == nil {
		return nil
	}
	m := map[string]int{}
	for name, v := range fonts {
		if r, ok := v.(pdfRef); ok {
			m[name] = int(r)
		}
	}
	return m
}

// resources finds a page's resources, inherited through /Parent.
func (x *pdfExtractor) resources(d pdfDict) pdfDict {
	for i := 0; d != nil && i < 32; i++ {
		if r := x.dict(d["Resources"]); r != nil {
			return r
		}
		d = x.dict(d["Parent"])
	}
	return nil
}

// mapFonts links content streams to their fonts: a page's /Contents to its
// resources, a form XObject to its own.
func (x *pdfExtractor) mapFonts() {
	x.fontsFor = map[int]map[string]int{}
	x.global = map[string]int{}
	for num, o := range x.doc.objs {
		d, ok := o.val.(pdfDict)
		if !ok {
			continue
		}
		if res := x.dict(d["Resources"]); res != nil {
			for n, f := range x.fontMap(res) {
				if _, seen := x.global[n]; !seen {
					x.global[n] = f
				}
			}
		}
		if o.isStm && d.name("Subtype") == "Form" {
			x.fontsFor[num] = x.fontMap(x.dict(d["Resources"]))
		}
		var contents []pdfRef
		switch c := d["Contents"].(type) {
		case pdfRef:
			if arr, ok := x.resolve(c).(pdfArray); ok {
				for _, e := range arr {
					if r, ok := e.(pdfRef); ok {
						contents = append(contents, r)
					}
				}
			} else {
				contents = append(contents, c)
			}
		case pdfArray:
			for _, e := range c {
				if r, ok := e.(pdfRef); ok {
					contents = append(contents, r)
				}
			}
		}
		if len(contents) > 0 {
			fm := x.fontMap(x.resources(d))
			for _, c := range contents {
				x.fontsFor[int(c)] = fm
			}
		}
	}
}

// isTextCandidate reports whether a stream may hold page content.
func isTextCandidate(d pdfDict) bool {
	switch d.name("Type") {
	case "ObjStm", "XRef", "Metadata", "EmbeddedFile", "CMap", "XObject":
		if d.name("Type") != "XObject" || d.name("Subtype") != "Form" {
			return false
		}
	}
	switch d.name("Subtype") {
	case "Image", "Type1C", "CIDFontType0C", "OpenType", "XML":
		return false
	}
	return d["Length1"] == nil && d["Length2"] == nil && d["Length3"] == nil // embedded font programs
}

func (x *pdfExtractor) run() error {
	x.mapFonts()
	for _, num := range x.doc.order {
		if err := x.st.ctx.Err(); err != nil {
			return err
		}
		o := x.doc.objs[num]
		d, _ := o.val.(pdfDict)
		if d == nil || !isTextCandidate(d) {
			continue
		}
		data, err := x.st.decodeStream(d, o.stream)
		switch {
		case errors.Is(err, errUnsupported), errors.Is(err, errCorrupt), errors.Is(err, errTooLarge):
			if x.st.archiveLeft <= 0 {
				x.unreadable = true
				return nil
			}
			if !errors.Is(err, errUnsupported) {
				x.unreadable = true
			}
			continue
		case err != nil:
			return err
		}
		if bytes.Contains(data, []byte("begincmap")) {
			continue
		}
		fonts := x.fontsFor[num]
		if fonts == nil {
			fonts = x.global
		}
		if err := x.content(data, fonts); err != nil {
			return err
		}
	}
	return nil
}

// content runs a content stream's text operators.
func (x *pdfExtractor) content(data []byte, fonts map[string]int) error {
	l := &pdfLexer{b: data}
	var ops []any
	font := -1
	for {
		t := l.next()
		switch t.kind {
		case tokEOF:
			return nil
		case tokDictOpen, tokArrOpen:
			l.back(t)
			v, _ := l.value(0)
			ops = append(ops, v)
			continue
		case tokDictClose, tokArrClose:
			continue
		case tokKeyword:
		default:
			if len(ops) < 64 {
				l.back(t)
				v, _ := l.value(0)
				ops = append(ops, v)
			}
			continue
		}
		var err error
		switch string(t.val) {
		case "ID": // inline image data runs to EI
			if i := bytes.Index(data[l.p:], []byte("EI")); i >= 0 {
				l.p += i + 2
			} else {
				l.p = len(data)
			}
		case "Tf":
			font = -1
			if len(ops) >= 2 {
				if n, ok := ops[len(ops)-2].(pdfName); ok {
					if f, ok := fonts[string(n)]; ok {
						font = f
					}
				}
			}
		case "Tj":
			err = x.show(ops, font, "")
		case "'", "\"":
			err = x.show(ops, font, "\n")
		case "TJ":
			if len(ops) > 0 {
				if arr, ok := ops[len(ops)-1].(pdfArray); ok {
					x.textOps++
					for _, e := range arr {
						switch v := e.(type) {
						case pdfString:
							err = x.write(x.decode(v, font))
						case float64:
							if v < -200 {
								err = x.write(" ")
							}
						}
						if err != nil {
							break
						}
					}
				}
			}
		case "T*", "ET":
			err = x.write("\n")
		case "Td", "TD":
			if len(ops) >= 2 {
				if ty, ok := ops[len(ops)-1].(float64); ok && ty != 0 {
					err = x.write("\n")
				} else {
					err = x.write(" ")
				}
			}
		case "Tm":
			err = x.write(" ")
		}
		if err != nil {
			return err
		}
		ops = ops[:0]
	}
}

func (x *pdfExtractor) show(ops []any, font int, before string) error {
	if len(ops) == 0 {
		return nil
	}
	s, ok := ops[len(ops)-1].(pdfString)
	if !ok {
		return nil
	}
	x.textOps++
	if err := x.write(before); err != nil {
		return err
	}
	return x.write(x.decode(s, font))
}

func (x *pdfExtractor) write(s string) error {
	if s == "" {
		return nil
	}
	return x.sink.WriteString(s)
}

// decode turns a string's codes into text with the font's ToUnicode map, or
// as UTF-16BE (with a BOM) or PDFDocEncoding. Text that comes out as control
// characters (glyph ids) is dropped and marks the result unreadable.
func (x *pdfExtractor) decode(s []byte, font int) string {
	if len(s) == 0 {
		return ""
	}
	if cm := x.cmap(font); cm != nil {
		out, ok := cm.decode(s)
		if !ok {
			x.unreadable = true
		}
		return out
	}
	var text string
	if len(s) >= 2 && s[0] == 0xfe && s[1] == 0xff {
		u := make([]uint16, 0, len(s)/2)
		for i := 2; i+1 < len(s); i += 2 {
			u = append(u, uint16(s[i])<<8|uint16(s[i+1]))
		}
		text = string(utf16.Decode(u))
	} else {
		var b strings.Builder
		for _, c := range s {
			b.WriteRune(pdfDocRune(c))
		}
		text = b.String()
	}
	bad := 0
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			bad++
		}
	}
	if bad*4 > utf8.RuneCountInString(text) {
		x.unreadable = true
		return ""
	}
	return text
}

// pdfDocRune maps a PDFDocEncoding byte; it matches Latin-1 except 0x80–0x9F.
func pdfDocRune(c byte) rune {
	if c >= 0x80 && c <= 0x9f {
		if r := pdfDoc80[c-0x80]; r != 0 {
			return r
		}
		return unicode.ReplacementChar
	}
	return rune(c)
}

var pdfDoc80 = [32]rune{
	'•', '†', '‡', '…', '—', '–', 'ƒ', '⁄', '‹', '›', '−', '‰', '„', '“', '”', '‘',
	'’', '‚', '™', 'ﬁ', 'ﬂ', 'Ł', 'Œ', 'Š', 'Ÿ', 'Ž', 'ı', 'ł', 'œ', 'š', 'ž', 0,
}

// cmap returns a font's ToUnicode map, read once.
func (x *pdfExtractor) cmap(font int) *pdfCMap {
	if font < 0 {
		return nil
	}
	if cm, ok := x.cmaps[font]; ok {
		return cm
	}
	x.cmaps[font] = nil
	fd := x.dict(pdfRef(font))
	ref, ok := fd["ToUnicode"].(pdfRef)
	if !ok {
		return nil
	}
	o := x.doc.objs[int(ref)]
	if o == nil || !o.isStm {
		return nil
	}
	sd, _ := o.val.(pdfDict)
	data, err := x.st.decodeStream(sd, o.stream)
	if err != nil {
		return nil
	}
	cm := parseCMap(data)
	x.cmaps[font] = cm
	return cm
}

// pdfCMap is a ToUnicode CMap: source codes of one width to text.
type pdfCMap struct {
	width int // bytes per code
	m     map[uint32]string
}

// pdfMaxCMapEntries bounds the codes one CMap may define.
const pdfMaxCMapEntries = 1 << 17

func parseCMap(data []byte) *pdfCMap {
	cm := &pdfCMap{m: map[uint32]string{}}
	l := &pdfLexer{b: data}
	var ops []any
	mode := ""
	for {
		t := l.next()
		if t.kind == tokEOF {
			break
		}
		if t.kind != tokKeyword {
			l.back(t)
			v, ok := l.value(0)
			if !ok {
				l.next()
				continue
			}
			ops = append(ops, v)
			if mode == "bfchar" && len(ops) == 2 {
				src, _ := ops[0].(pdfString)
				dst, _ := ops[1].(pdfString)
				cm.add(src, dst)
				ops = ops[:0]
			}
			if mode == "bfrange" && len(ops) == 3 {
				cm.addRange(ops)
				ops = ops[:0]
			}
			continue
		}
		switch string(t.val) {
		case "beginbfchar":
			mode = "bfchar"
		case "beginbfrange":
			mode = "bfrange"
		case "endbfchar", "endbfrange":
			mode = ""
		}
		ops = ops[:0]
		if len(cm.m) > pdfMaxCMapEntries {
			break
		}
	}
	if cm.width == 0 {
		return nil
	}
	return cm
}

func codeOf(b []byte) uint32 {
	var c uint32
	for _, x := range b {
		c = c<<8 | uint32(x)
	}
	return c
}

func utf16beText(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
	}
	if len(b)%2 == 1 {
		u = append(u, uint16(b[len(b)-1]))
	}
	return string(utf16.Decode(u))
}

func (cm *pdfCMap) add(src, dst []byte) {
	if len(src) == 0 || len(src) > 4 || len(cm.m) > pdfMaxCMapEntries {
		return
	}
	if cm.width == 0 {
		cm.width = len(src)
	}
	if len(src) != cm.width {
		return
	}
	cm.m[codeOf(src)] = utf16beText(dst)
}

func (cm *pdfCMap) addRange(ops []any) {
	lo, ok1 := ops[0].(pdfString)
	hi, ok2 := ops[1].(pdfString)
	if !ok1 || !ok2 || len(lo) == 0 || len(lo) > 4 || len(lo) != len(hi) {
		return
	}
	a, b := codeOf(lo), codeOf(hi)
	if b < a || b-a > pdfMaxCMapEntries {
		return
	}
	switch dst := ops[2].(type) {
	case pdfString:
		if len(dst) == 0 {
			return
		}
		base := append([]byte(nil), dst...)
		for c := a; c <= b && len(cm.m) <= pdfMaxCMapEntries; c++ {
			code := encodeCode(c, len(lo))
			cm.add(code, base)
			base = incLast(base)
		}
	case pdfArray:
		for i, e := range dst {
			s, ok := e.(pdfString)
			if !ok || a+uint32(i) > b { // #nosec G115 -- i < len(dst) ≤ entries cap
				continue
			}
			cm.add(encodeCode(a+uint32(i), len(lo)), s) // #nosec G115 -- as above
		}
	}
}

func encodeCode(c uint32, width int) []byte {
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = byte(c)
		c >>= 8
	}
	return out
}

// incLast increments the last UTF-16 unit of a bfrange destination.
func incLast(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// decode maps a string's codes; ok is false when a code had no mapping.
func (cm *pdfCMap) decode(s []byte) (string, bool) {
	var b strings.Builder
	ok := true
	for i := 0; i+cm.width <= len(s); i += cm.width {
		t, found := cm.m[codeOf(s[i:i+cm.width])]
		if !found {
			ok = false
			continue
		}
		b.WriteString(t)
	}
	return b.String(), ok
}
