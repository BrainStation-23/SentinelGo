package filescan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"path"
	"strings"
)

// scanZip scans a zip-based file: an Office Open XML document, an
// OpenDocument file, or a plain archive whose entries are scanned on their own.
func (st *scanState) scanZip(ra io.ReaderAt, size int64, depth int, name string) docResult {
	if n, ok := zipEntryCount(ra, size); ok && n > maxDirEntries {
		return docResult{typ: "archive.zip", status: Unscannable(ReasonTooLarge)}
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return docResult{typ: "archive.zip", status: Unscannable(ReasonCorrupt)}
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	switch {
	case files["[Content_Types].xml"] != nil:
		return st.scanOOXML(zr, files)
	case isODF(files["mimetype"]):
		return st.scanODF(zr, files)
	default:
		return st.scanArchive(zr, depth, name)
	}
}

// zipEntryCount reads the entry count from the end of central directory
// record (zip64 aware), so an archive claiming millions of entries is
// refused before archive/zip allocates a record for each. ok is false when
// the record isn't found; archive/zip then reports the archive as corrupt.
func zipEntryCount(ra io.ReaderAt, size int64) (uint64, bool) {
	const eocdLen, maxComment = 22, 0xffff
	tail := min(size, eocdLen+maxComment)
	buf := make([]byte, tail)
	if _, err := ra.ReadAt(buf, size-tail); err != nil && err != io.EOF {
		return 0, false
	}
	i := bytes.LastIndex(buf, []byte("PK\x05\x06"))
	if i < 0 || len(buf)-i < eocdLen {
		return 0, false
	}
	n := uint64(binary.LittleEndian.Uint16(buf[i+10:]))
	if n != 0xffff || i < 20 || string(buf[i-20:i-16]) != "PK\x06\x07" {
		return n, true
	}
	// zip64: the locator before the record points at the zip64 record.
	off, ok := toInt64(binary.LittleEndian.Uint64(buf[i-20+8:]))
	rec := make([]byte, 40)
	if !ok || off > size-40 {
		return 0, false
	}
	if _, err := ra.ReadAt(rec, off); err != nil || string(rec[:4]) != "PK\x06\x06" {
		return 0, false
	}
	return binary.LittleEndian.Uint64(rec[32:]), true
}

// openEntry opens a zip entry for reading within the archive limits. The
// declared sizes can lie, so the reader is limited too.
func (st *scanState) openEntry(f *zip.File) (io.ReadCloser, error) {
	if f.Flags&0x1 != 0 {
		return nil, errEncrypted
	}
	size, ok := toInt64(f.UncompressedSize64)
	if !ok || size > st.archiveLeft || size > st.s.limits.MaxFileBytes {
		return nil, errTooLarge
	}
	if c, ok := toInt64(f.CompressedSize64); ok && c > 0 && size > 1<<20 && size/c > st.s.limits.MaxRatio {
		return nil, errTooLarge // zip bomb
	}
	rc, err := f.Open()
	if err != nil {
		if errors.Is(err, zip.ErrAlgorithm) {
			return nil, errUnsupported
		}
		return nil, errCorrupt
	}
	limit := min(st.archiveLeft, st.s.limits.MaxFileBytes)
	return &budgetReader{st: st, r: ctxReader{st.ctx, rc}, c: rc, left: limit}, nil
}

// toInt64 converts a size from a zip header, or reports false when it is
// too big for an int64 (such a header is lying anyway).
func toInt64(n uint64) (int64, bool) {
	if n > math.MaxInt64 {
		return 0, false
	}
	return int64(n), true // #nosec G115 -- checked against MaxInt64 above
}

var (
	errEncrypted   = errors.New("encrypted entry")
	errUnsupported = errors.New("unsupported")
)

// budgetReader charges what it reads to the archive budget and fails, rather
// than truncating, when an entry is bigger than it said.
type budgetReader struct {
	st   *scanState
	r    io.Reader
	c    io.Closer
	left int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	b.st.archiveLeft -= int64(n)
	return n, err
}

func (b *budgetReader) Close() error { return b.c.Close() }

// entryStatus maps an openEntry/extract error to a status.
func (st *scanState) entryStatus(err error) string {
	switch {
	case errors.Is(err, errEncrypted):
		return Unscannable(ReasonPasswordProtected)
	case errors.Is(err, errUnsupported):
		return Unscannable(ReasonUnsupportedType)
	case errors.Is(err, errXML):
		return Unscannable(ReasonCorrupt)
	default:
		return statusFor(st.ctx, err)
	}
}

// ooxmlParts says which parts of an Office Open XML package hold text.
func ooxmlTextPart(name string) bool {
	if !strings.HasSuffix(name, ".xml") || strings.Contains(name, "/_rels/") {
		return false
	}
	switch {
	case strings.HasPrefix(name, "word/"):
		base := path.Base(name)
		return base == "document.xml" || base == "footnotes.xml" || base == "endnotes.xml" || base == "comments.xml" ||
			strings.HasPrefix(base, "header") || strings.HasPrefix(base, "footer")
	case strings.HasPrefix(name, "xl/"):
		return name == "xl/sharedStrings.xml" || strings.HasPrefix(name, "xl/worksheets/sheet") || strings.HasPrefix(name, "xl/comments")
	case strings.HasPrefix(name, "ppt/"):
		return strings.HasPrefix(name, "ppt/slides/slide") || strings.HasPrefix(name, "ppt/notesSlides/") || strings.HasPrefix(name, "ppt/comments/")
	}
	return false
}

func ooxmlType(files map[string]*zip.File) string {
	switch {
	case files["word/document.xml"] != nil:
		return "ooxml.docx"
	case files["xl/workbook.xml"] != nil:
		return "ooxml.xlsx"
	case files["ppt/presentation.xml"] != nil:
		return "ooxml.pptx"
	}
	return "ooxml"
}

// scanOOXML extracts the text parts of a docx, xlsx or pptx, plus its
// sensitivity labels. Embedded files (word/embeddings) aren't opened yet.
func (st *scanState) scanOOXML(zr *zip.Reader, files map[string]*zip.File) docResult {
	typ := ooxmlType(files)
	var labels []string
	if f := files["docProps/custom.xml"]; f != nil {
		if rc, err := st.openEntry(f); err == nil {
			labels = labelNames(rc)
			_ = rc.Close()
		}
	}
	sink := newSink(st)
	status := StatusScanned
	for _, f := range zr.File {
		if !ooxmlTextPart(f.Name) {
			continue
		}
		err := st.extractEntry(f, sink)
		if errors.Is(err, errTextLimit) || st.ctx.Err() != nil {
			break
		}
		if err != nil {
			status = worse(status, st.entryStatus(err))
		}
	}
	d := st.finishDoc(typ, sink, st.ctx.Err())
	d.status, d.labels = worse(d.status, status), labels
	return d
}

func (st *scanState) extractEntry(f *zip.File, sink *textSink) error {
	rc, err := st.openEntry(f)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	return extractXMLText(rc, sink)
}

func isODF(f *zip.File) bool {
	if f == nil || f.UncompressedSize64 > 128 {
		return false
	}
	rc, err := f.Open()
	if err != nil {
		return false
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(io.LimitReader(rc, 128))
	return strings.HasPrefix(string(b), "application/vnd.oasis.opendocument.")
}

// scanODF extracts content.xml of an OpenDocument file. Password-protected
// ones list encryption data in their manifest.
func (st *scanState) scanODF(zr *zip.Reader, files map[string]*zip.File) docResult {
	typ := "odf"
	if rc, err := files["mimetype"].Open(); err == nil {
		b, _ := io.ReadAll(io.LimitReader(rc, 128))
		_ = rc.Close()
		typ = "odf." + strings.TrimPrefix(strings.TrimSpace(string(b)), "application/vnd.oasis.opendocument.")
	}
	if m := files["META-INF/manifest.xml"]; m != nil {
		if rc, err := st.openEntry(m); err == nil {
			b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
			_ = rc.Close()
			if bytes.Contains(b, []byte("encryption-data")) {
				return docResult{typ: typ, status: Unscannable(ReasonPasswordProtected)}
			}
		}
	}
	f := files["content.xml"]
	if f == nil {
		return docResult{typ: typ, status: Unscannable(ReasonCorrupt)}
	}
	sink := newSink(st)
	err := st.extractEntry(f, sink)
	d := st.finishDoc(typ, sink, nil)
	if err != nil && !errors.Is(err, errTextLimit) {
		d.status = worse(d.status, st.entryStatus(err))
	}
	return d
}

// scanArchive scans every entry of a plain zip on its own, as a file of its
// own type. Entries with findings or a status other than scanned are recorded
// in st.entries. The archive's own status covers the archive itself (too
// deep, too many entries); the caller adds the entries' statuses.
func (st *scanState) scanArchive(zr *zip.Reader, depth int, name string) docResult {
	d := docResult{typ: "archive.zip", status: StatusScanned}
	if depth >= st.s.limits.MaxDepth {
		d.status = Unscannable(ReasonTooLarge)
		return d
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if st.ctx.Err() != nil {
			d.status = worse(d.status, StatusTimeout)
			return d
		}
		if st.entriesLeft <= 0 || st.textLeft <= 0 {
			// Out of budget: the rest isn't scanned.
			d.status = worse(d.status, StatusTruncated)
			if st.entriesLeft <= 0 {
				d.status = worse(d.status, Unscannable(ReasonTooLarge))
			}
			return d
		}
		st.entriesLeft--
		entryName := path.Join(name, f.Name) // #nosec G305 -- a label for results, never a path anything is written to
		e := st.scanEntry(f, depth, entryName)
		if len(e.Findings) > 0 || e.Status != StatusScanned {
			st.entries = append(st.entries, e)
		}
	}
	return d
}

// scanEntry reads one archive entry into memory or a spill file and scans it
// as a document of its own.
func (st *scanState) scanEntry(f *zip.File, depth int, name string) Entry {
	e := Entry{Name: name}
	rc, err := st.openEntry(f)
	if err != nil {
		e.Status = st.entryStatus(err)
		return e
	}
	ra, size, cleanup, err := st.s.spill(rc, int64(min(f.UncompressedSize64, memSpillLimit)))
	_ = rc.Close()
	if err != nil {
		e.Status = st.entryStatus(err)
		return e
	}
	defer cleanup()
	doc := st.scanDoc(ra, size, depth+1, name)
	e.DetectedType, e.Status, e.Findings, e.Labels = doc.typ, doc.status, doc.findings, doc.labels
	return e
}
