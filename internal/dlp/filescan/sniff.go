package filescan

import (
	"bytes"
	"io"
	"unicode/utf8"
)

// sniffBytes is how much of a file type detection looks at.
const sniffBytes = 8 << 10

// kind is a file's format family, from its content.
type kind int

const (
	kindBinary kind = iota // nothing we can read
	kindText
	kindZip // archive, OOXML or ODF: told apart by zipKind
	kindRTF
	kindCFB // OLE compound file: legacy Office, or encrypted OOXML
	kindPDF
)

// sniffed is the outcome of type detection.
type sniffed struct {
	kind kind
	typ  string   // detected_type
	enc  encoding // kindText only
}

// magic is a format this package can't read, so it is reported as
// unsupported with a useful type instead of "binary".
type magic struct {
	off   int
	magic string
	typ   string
}

// strongMagic can't start a text file (it has bytes text doesn't contain).
var strongMagic = []magic{
	{0, "\x89PNG\r\n\x1a\n", "image.png"},
	{0, "\xff\xd8\xff", "image.jpeg"},
	{0, "II*\x00", "image.tiff"},
	{0, "MM\x00*", "image.tiff"},
	{0, "\x1f\x8b", "archive.gzip"},
	{0, "7z\xbc\xaf\x27\x1c", "archive.7z"},
	{0, "Rar!\x1a\x07", "archive.rar"},
	{0, "\xfd7zXZ\x00", "archive.xz"},
	{0, "\x7fELF", "executable.elf"},
	{0, "\xcf\xfa\xed\xfe", "executable.macho"},
	{0, "\xca\xfe\xba\xbe", "executable.macho"},
	{0, "SQLite format 3\x00", "database.sqlite"},
}

// weakMagic is plain ASCII ("BMW,Q3,…" starts like a bitmap), so it only
// names a file that has already failed the text test.
var weakMagic = []magic{
	{0, "GIF87a", "image.gif"},
	{0, "GIF89a", "image.gif"},
	{0, "BM", "image.bmp"},
	{0, "RIFF", "media.riff"},
	{4, "ftyp", "media.mp4"},
	{0, "BZh", "archive.bzip2"},
	{0, "MZ", "executable.pe"},
}

func matchMagic(head []byte, list []magic) (string, bool) {
	for _, m := range list {
		if len(head) >= m.off+len(m.magic) && string(head[m.off:m.off+len(m.magic)]) == m.magic {
			return m.typ, true
		}
	}
	return "", false
}

// sniff detects the type from the first bytes of a file.
func sniff(head []byte) sniffed {
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return sniffed{kind: kindZip, typ: "archive.zip"}
	case bytes.HasPrefix(head, []byte("{\\rtf")):
		return sniffed{kind: kindRTF, typ: "rtf"}
	case bytes.HasPrefix(head, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
		return sniffed{kind: kindCFB, typ: "ole"}
	case bytes.HasPrefix(head, []byte("%PDF-")):
		return sniffed{kind: kindPDF, typ: "pdf"}
	}
	if typ, ok := matchMagic(head, strongMagic); ok {
		return sniffed{kind: kindBinary, typ: typ}
	}
	if enc, ok := textEncoding(head); ok {
		return sniffed{kind: kindText, typ: "text." + enc.name(), enc: enc}
	}
	if typ, ok := matchMagic(head, weakMagic); ok {
		return sniffed{kind: kindBinary, typ: typ}
	}
	return sniffed{kind: kindBinary, typ: "binary"}
}

// textEncoding decides whether head is text, and in which encoding. Without a
// byte order mark it looks for UTF-16 by its zero bytes, then valid UTF-8,
// then Latin-1 text (few control characters).
func textEncoding(head []byte) (encoding, bool) {
	switch {
	case bytes.HasPrefix(head, []byte("\xef\xbb\xbf")):
		return encUTF8, true
	case bytes.HasPrefix(head, []byte("\xff\xfe")):
		return encUTF16LE, true
	case bytes.HasPrefix(head, []byte("\xfe\xff")):
		return encUTF16BE, true
	}
	if len(head) == 0 {
		return encUTF8, true
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return utf16WithoutBOM(head)
	}
	if utf8.Valid(trimPartialRune(head)) {
		return encUTF8, controlRatioOK(head)
	}
	return encLatin1, controlRatioOK(head)
}

// utf16WithoutBOM recognises mostly-ASCII UTF-16: zero bytes in (almost) all
// odd positions for little endian, even positions for big endian.
func utf16WithoutBOM(head []byte) (encoding, bool) {
	var evenZero, oddZero int
	pairs := len(head) / 2
	if pairs < 4 {
		return 0, false
	}
	for i := 0; i+1 < len(head); i += 2 {
		if head[i] == 0 {
			evenZero++
		}
		if head[i+1] == 0 {
			oddZero++
		}
	}
	switch {
	case oddZero*10 >= pairs*7 && evenZero*20 < pairs:
		return encUTF16LE, true
	case evenZero*10 >= pairs*7 && oddZero*20 < pairs:
		return encUTF16BE, true
	}
	return 0, false
}

// controlRatioOK reports whether head has few enough control characters to
// be text: at most 1 in 100, not counting tab, newline, carriage return and
// form feed.
func controlRatioOK(head []byte) bool {
	ctrl := 0
	for _, b := range head {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != '\f' || b == 0x7f {
			ctrl++
		}
	}
	return ctrl*100 <= len(head)
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of b (the
// sniff window can end in the middle of one).
func trimPartialRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}

// readHead reads up to sniffBytes from the start of ra.
func readHead(ra io.ReaderAt, size int64) ([]byte, error) {
	head := make([]byte, min(size, sniffBytes))
	n, err := ra.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return head[:n], nil
}

// scanDoc detects the type of ra and scans it. name is the archive path of
// an entry ("" for the file itself); depth is how deep in archives it is.
func (st *scanState) scanDoc(ra io.ReaderAt, size int64, depth int, name string) docResult {
	head, err := readHead(ra, size)
	if err != nil {
		return docResult{typ: "binary", status: statusFor(st.ctx, err)}
	}
	sn := sniff(head)
	switch sn.kind {
	case kindText:
		sink := newSink(st)
		err := decodeText(io.NewSectionReader(ra, 0, size), sn.enc, sink)
		return st.finishDoc(sn.typ, sink, err)
	case kindRTF:
		sink := newSink(st)
		err := extractRTF(io.NewSectionReader(ra, 0, size), sink)
		return st.finishDoc(sn.typ, sink, err)
	case kindZip:
		return st.scanZip(ra, size, depth, name)
	case kindCFB:
		return st.scanCFB(ra, size)
	default: // binary, PDF (no extractor yet), images, executables
		return docResult{typ: sn.typ, status: Unscannable(ReasonUnsupportedType)}
	}
}
