package filescan

// Compressed RTF (MS-OXRTFCP), the body Outlook keeps in PR_RTF_COMPRESSED
// when a message has no plain or HTML body. A 16-byte header (compressed
// size, raw size, type, CRC) is followed, for type "LZFu", by an LZ77 stream
// over a 4 KiB circular dictionary preloaded with common RTF; type "MELA"
// holds the RTF as is. The stream is decoded as it is read, never into one
// buffer, and stops at the declared raw size.

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

const (
	lzfuHeaderLen  = 16
	lzfuDictSize   = 4096
	lzfuCompressed = 0x75465a4c // "LZFu"
	lzfuRaw        = 0x414c454d // "MELA"
)

// lzfuPreload is the dictionary's initial content.
const lzfuPreload = `{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}{\f0\fnil \froman \fswiss \fmodern \fscript \fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\colortbl\red0\green0\blue0` +
	"\r\n" + `\par \pard\plain\f0\fs20\b\i\u\tab\tx`

var errLZFu = errors.New("compressed RTF: corrupt")

// lzfuCRC is the stream's CRC: CRC-32 (IEEE) without the initial and final
// inversion.
func lzfuCRC(b []byte) uint32 { return ^crc32.Update(^uint32(0), crc32.IEEETable, b) }

// newLZFuReader checks the header of a compressed RTF stream and returns a
// reader of the RTF it holds.
func newLZFuReader(b []byte) (io.Reader, error) {
	if len(b) < lzfuHeaderLen {
		return nil, errLZFu
	}
	compSize := binary.LittleEndian.Uint32(b[0:])
	rawSize := binary.LittleEndian.Uint32(b[4:])
	typ := binary.LittleEndian.Uint32(b[8:])
	crc := binary.LittleEndian.Uint32(b[12:])
	// compSize counts everything after itself; a writer may pad the stream.
	if compSize < lzfuHeaderLen-4 || uint64(compSize)+4 > uint64(len(b)) {
		return nil, errLZFu
	}
	data := b[lzfuHeaderLen : compSize+4]
	switch typ {
	case lzfuRaw:
		if uint64(rawSize) > uint64(len(data)) {
			return nil, errLZFu
		}
		return &lzfuRawReader{b: data[:rawSize]}, nil
	case lzfuCompressed:
		if lzfuCRC(data) != crc {
			return nil, errLZFu
		}
		r := &lzfuReader{src: data, left: int64(rawSize), wpos: len(lzfuPreload)}
		copy(r.dict[:], lzfuPreload)
		return r, nil
	}
	return nil, errLZFu
}

type lzfuRawReader struct{ b []byte }

func (r *lzfuRawReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// lzfuReader decodes an LZFu stream. Each control byte says, low bit first,
// whether the next 8 tokens are literal bytes (0) or 2-byte big-endian
// references (1): a 12-bit dictionary offset and a 4-bit length (+2). A
// reference to the write position itself ends the stream.
type lzfuReader struct {
	src  []byte
	dict [lzfuDictSize]byte
	wpos int
	left int64 // raw bytes still expected
	out  []byte
	buf  [8 * 17]byte // one control byte's worth of output at most
	done bool
	err  error
}

func (r *lzfuReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.done || r.left <= 0 {
			return 0, io.EOF
		}
		if r.err != nil {
			return 0, r.err
		}
		r.fill()
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *lzfuReader) put(c byte) {
	r.dict[r.wpos] = c
	r.wpos = (r.wpos + 1) % lzfuDictSize
	if r.left > 0 {
		r.out = append(r.out, c)
		r.left--
	}
}

// fill decodes the tokens of one control byte into r.out.
func (r *lzfuReader) fill() {
	r.out = r.buf[:0]
	if len(r.src) == 0 {
		r.err = io.ErrUnexpectedEOF // no end marker before the data ran out
		return
	}
	ctrl := r.src[0]
	r.src = r.src[1:]
	for bit := 0; bit < 8; bit++ {
		if ctrl&(1<<bit) == 0 {
			if len(r.src) < 1 {
				r.err = io.ErrUnexpectedEOF
				return
			}
			r.put(r.src[0])
			r.src = r.src[1:]
			continue
		}
		if len(r.src) < 2 {
			r.err = io.ErrUnexpectedEOF
			return
		}
		ref := int(binary.BigEndian.Uint16(r.src))
		r.src = r.src[2:]
		off, n := ref>>4, ref&0xf+2
		if off == r.wpos {
			r.done = true
			return
		}
		for i := 0; i < n; i++ {
			r.put(r.dict[(off+i)%lzfuDictSize])
		}
	}
}
