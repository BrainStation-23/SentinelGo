package filescan

import (
	"errors"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// encoding is a plain-text file's character encoding.
type encoding int

const (
	encUTF8 encoding = iota
	encUTF16LE
	encUTF16BE
	encLatin1
)

func (e encoding) name() string {
	switch e {
	case encUTF16LE:
		return "utf16le"
	case encUTF16BE:
		return "utf16be"
	case encLatin1:
		return "latin1"
	default:
		return "utf8"
	}
}

// textReadBytes is how much a text decoder reads at a time.
const textReadBytes = 64 << 10

// decodeText converts r from enc to UTF-8 and writes it to sink. A byte order
// mark is dropped. Invalid UTF-8 is passed through (the detectors work on
// bytes); unpaired UTF-16 surrogates become U+FFFD.
func decodeText(r io.Reader, enc encoding, sink *textSink) error {
	buf := make([]byte, textReadBytes)
	var carry []byte // bytes of a character split across reads
	first := true
	var sb strings.Builder
	for {
		n, rerr := r.Read(buf)
		data := append(carry, buf[:n]...)
		carry = nil
		if first && len(data) > 0 {
			data, first = dropBOM(data, enc), false
		}
		sb.Reset()
		switch enc {
		case encUTF16LE, encUTF16BE:
			carry = decodeUTF16(data, enc == encUTF16BE, rerr != nil, &sb)
		case encLatin1:
			for _, b := range data {
				sb.WriteRune(rune(b))
			}
		default:
			keep := data
			if rerr == nil {
				keep = trimPartialRune(data)
				carry = append([]byte(nil), data[len(keep):]...)
			}
			sb.Write(keep)
		}
		if sb.Len() > 0 {
			if err := sink.WriteString(sb.String()); err != nil {
				return err
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}

func dropBOM(data []byte, enc encoding) []byte {
	switch {
	case enc == encUTF8 && len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf":
		return data[3:]
	case enc == encUTF16LE && len(data) >= 2 && string(data[:2]) == "\xff\xfe",
		enc == encUTF16BE && len(data) >= 2 && string(data[:2]) == "\xfe\xff":
		return data[2:]
	}
	return data
}

// decodeUTF16 writes the UTF-8 form of data to sb and returns the bytes of a
// character that continues in the next read (an odd byte, or the high half of
// a surrogate pair). At the end (last) nothing is carried.
func decodeUTF16(data []byte, bigEndian, last bool, sb *strings.Builder) []byte {
	unit := func(i int) uint16 {
		if bigEndian {
			return uint16(data[i])<<8 | uint16(data[i+1])
		}
		return uint16(data[i+1])<<8 | uint16(data[i])
	}
	i := 0
	for ; i+1 < len(data); i += 2 {
		u := unit(i)
		switch {
		case utf16.IsSurrogate(rune(u)) && u < 0xdc00: // high surrogate
			if i+3 >= len(data) {
				if !last {
					return append([]byte(nil), data[i:]...)
				}
				sb.WriteRune(utf8.RuneError)
				continue
			}
			if r := utf16.DecodeRune(rune(u), rune(unit(i+2))); r != utf8.RuneError {
				sb.WriteRune(r)
				i += 2
				continue
			}
			sb.WriteRune(utf8.RuneError)
		case utf16.IsSurrogate(rune(u)): // unpaired low surrogate
			sb.WriteRune(utf8.RuneError)
		default:
			sb.WriteRune(rune(u))
		}
	}
	if i < len(data) && !last {
		return append([]byte(nil), data[i:]...)
	}
	return nil
}
