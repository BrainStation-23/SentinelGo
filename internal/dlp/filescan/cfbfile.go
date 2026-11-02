package filescan

import (
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf16"
)

// A reader for OLE compound files (MS-CFB), the container of legacy Office
// documents. The input is hostile: every sector number is range-checked and
// every chain is bounded by the number of sectors in the file, so a loop or
// a huge stream can't stall or exhaust the scanner.

const (
	cfbEndOfChain = 0xFFFFFFFE
	cfbFree       = 0xFFFFFFFF
	cfbNoStream   = 0xFFFFFFFF
	cfbHeaderLen  = 512
	cfbDirEntry   = 128

	cfbTypeStorage = 1
	cfbTypeStream  = 2
	cfbTypeRoot    = 5
)

var errCFB = errors.New("malformed compound file")

// cfbEntry is one directory entry.
type cfbEntry struct {
	name               string
	typ                byte
	left, right, child uint32
	start              uint32
	size               uint64
}

// cfbFile is a parsed compound file.
type cfbFile struct {
	ra          io.ReaderAt
	size        int64
	sectorShift uint
	fat         []uint32
	miniFAT     []uint32
	miniStream  []byte // the root entry's stream, holding the small streams
	cutoff      uint64
	entries     []cfbEntry
	maxStream   int64
}

// openCFB parses the header, allocation tables and directory. maxStream
// bounds any one stream read later.
func openCFB(ra io.ReaderAt, size, maxStream int64) (*cfbFile, error) {
	if size < cfbHeaderLen {
		return nil, errCFB
	}
	hdr := make([]byte, cfbHeaderLen)
	if _, err := ra.ReadAt(hdr, 0); err != nil {
		return nil, errCFB
	}
	le := binary.LittleEndian
	shift := uint(le.Uint16(hdr[0x1E:]))
	if (shift != 9 && shift != 12) || le.Uint16(hdr[0x20:]) != 6 {
		return nil, errCFB
	}
	f := &cfbFile{ra: ra, size: size, sectorShift: shift, cutoff: uint64(le.Uint32(hdr[0x38:])), maxStream: maxStream}
	sectorSize := int64(1) << shift
	nSectors := (size - sectorSize) / sectorSize // sectors after the header
	if nSectors <= 0 || nSectors > 1<<24 {
		return nil, errCFB
	}

	// FAT sector numbers: 109 in the header, then the DIFAT chain.
	nFAT := le.Uint32(hdr[0x2C:])
	if int64(nFAT) > nSectors {
		return nil, errCFB
	}
	wantFAT := int(nFAT) // at most nSectors (< 2^24)
	var fatSectors []uint32
	for i := 0; i < 109 && len(fatSectors) < wantFAT; i++ {
		fatSectors = append(fatSectors, le.Uint32(hdr[0x4C+4*i:]))
	}
	difat := le.Uint32(hdr[0x44:])
	perDIFAT := int(sectorSize/4) - 1
	for hops := int64(0); len(fatSectors) < wantFAT && difat < cfbEndOfChain; hops++ {
		if hops > nSectors {
			return nil, errCFB
		}
		sec, err := f.sector(difat, nSectors)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perDIFAT && len(fatSectors) < wantFAT; i++ {
			fatSectors = append(fatSectors, le.Uint32(sec[4*i:]))
		}
		difat = le.Uint32(sec[4*perDIFAT:])
	}
	for _, s := range fatSectors {
		sec, err := f.sector(s, nSectors)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(sec); i += 4 {
			f.fat = append(f.fat, le.Uint32(sec[i:]))
		}
	}

	dir, err := f.chain(le.Uint32(hdr[0x30:]), -1)
	if err != nil {
		return nil, err
	}
	for off := 0; off+cfbDirEntry <= len(dir); off += cfbDirEntry {
		f.entries = append(f.entries, parseCFBEntry(dir[off:off+cfbDirEntry]))
	}
	if len(f.entries) == 0 || f.entries[0].typ != cfbTypeRoot {
		return nil, errCFB
	}
	if first := le.Uint32(hdr[0x3C:]); first < cfbEndOfChain {
		mf, err := f.chain(first, -1)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(mf); i += 4 {
			f.miniFAT = append(f.miniFAT, le.Uint32(mf[i:]))
		}
	}
	if root := f.entries[0]; root.start < cfbEndOfChain && root.size > 0 {
		limit, ok := toInt64(root.size)
		if !ok || limit > maxStream {
			limit = maxStream
		}
		if f.miniStream, err = f.chain(root.start, limit); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func parseCFBEntry(b []byte) cfbEntry {
	le := binary.LittleEndian
	nameLen := int(le.Uint16(b[0x40:]))
	if nameLen > 64 {
		nameLen = 64
	}
	units := make([]uint16, 0, 32)
	for i := 0; i+1 < nameLen; i += 2 {
		if u := le.Uint16(b[i:]); u != 0 {
			units = append(units, u)
		}
	}
	return cfbEntry{
		name: string(utf16.Decode(units)), typ: b[0x42],
		left: le.Uint32(b[0x44:]), right: le.Uint32(b[0x48:]), child: le.Uint32(b[0x4C:]),
		start: le.Uint32(b[0x74:]), size: le.Uint64(b[0x78:]),
	}
}

// sector reads sector n (of nSectors).
func (f *cfbFile) sector(n uint32, nSectors int64) ([]byte, error) {
	if int64(n) >= nSectors {
		return nil, errCFB
	}
	size := int64(1) << f.sectorShift
	b := make([]byte, size)
	if _, err := f.ra.ReadAt(b, (int64(n)+1)*size); err != nil && err != io.EOF {
		return nil, errCFB
	}
	return b, nil
}

// chain reads the sectors of a FAT chain, up to limit bytes (-1: no limit
// beyond the file).
func (f *cfbFile) chain(start uint32, limit int64) ([]byte, error) {
	size := int64(1) << f.sectorShift
	nSectors := (f.size - size) / size
	var out []byte
	for s, hops := start, int64(0); s < cfbEndOfChain; hops++ {
		if hops > nSectors || int(s) >= len(f.fat) {
			return nil, errCFB
		}
		if limit >= 0 && int64(len(out)) >= limit {
			break
		}
		b, err := f.sector(s, nSectors)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		s = f.fat[s]
	}
	if limit >= 0 && int64(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

// miniChain reads a stream stored in the mini stream.
func (f *cfbFile) miniChain(start uint32, size int64) ([]byte, error) {
	const mini = 64
	var out []byte
	for s, hops := start, 0; s < cfbEndOfChain && int64(len(out)) < size; hops++ {
		if hops > len(f.miniFAT) || int(s) >= len(f.miniFAT) {
			return nil, errCFB
		}
		off := int(s) * mini
		if off+mini > len(f.miniStream) {
			return nil, errCFB
		}
		out = append(out, f.miniStream[off:off+mini]...)
		s = f.miniFAT[s]
	}
	if int64(len(out)) < size {
		return nil, errCFB
	}
	return out[:size], nil
}

// read returns a stream's bytes, or errTooLarge past maxStream.
func (f *cfbFile) read(e cfbEntry) ([]byte, error) {
	if e.typ != cfbTypeStream {
		return nil, errCFB
	}
	size, ok := toInt64(e.size)
	if !ok || size > f.maxStream {
		return nil, errTooLarge
	}
	if e.size < f.cutoff {
		return f.miniChain(e.start, size)
	}
	b, err := f.chain(e.start, size)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) < size {
		return nil, errCFB
	}
	return b, nil
}

// children returns the entries directly under storage entry i, walking its
// red-black tree without recursion and with a visit bound.
func (f *cfbFile) children(i int) []cfbEntry {
	var out []cfbEntry
	stack := []uint32{f.entries[i].child}
	seen := map[uint32]bool{}
	for len(stack) > 0 && len(seen) <= len(f.entries) {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == cfbNoStream || int(n) >= len(f.entries) || seen[n] {
			continue
		}
		seen[n] = true
		e := f.entries[n]
		out = append(out, e)
		stack = append(stack, e.left, e.right)
	}
	return out
}

// top returns the root's direct children by name.
func (f *cfbFile) top() map[string]cfbEntry {
	m := map[string]cfbEntry{}
	for _, e := range f.children(0) {
		m[e.name] = e
	}
	return m
}
