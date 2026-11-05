package filescan

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// lzfuCompress is a small LZFu encoder for tests: greedy longest matches in
// the dictionary, each checked by replaying the decoder, so a reference is
// right however it overlaps the write position.
func lzfuCompress(raw []byte) []byte {
	var dict [lzfuDictSize]byte
	copy(dict[:], lzfuPreload)
	wpos := len(lzfuPreload)
	var body, group []byte
	var ctrl byte
	tokens := 0
	flush := func() {
		body = append(body, ctrl)
		body = append(body, group...)
		ctrl, group, tokens = 0, nil, 0
	}
	put := func(c byte) { dict[wpos] = c; wpos = (wpos + 1) % lzfuDictSize }
	replay := func(off, n int) []byte { // what a reference would produce
		d, w := dict, wpos
		out := make([]byte, n)
		for i := range out {
			out[i] = d[(off+i)%lzfuDictSize]
			d[w] = out[i]
			w = (w + 1) % lzfuDictSize
		}
		return out
	}
	for i := 0; i < len(raw); {
		bestOff, bestLen := 0, 0
		for off := 0; off < lzfuDictSize; off++ {
			if off == wpos {
				continue // that reference ends the stream
			}
			maxLen := min(17, len(raw)-i)
			if maxLen < 2 || dict[off] != raw[i] {
				continue
			}
			got := replay(off, maxLen)
			n := 0
			for n < maxLen && got[n] == raw[i+n] {
				n++
			}
			if n > bestLen {
				bestOff, bestLen = off, n
			}
		}
		if bestLen >= 2 {
			ctrl |= 1 << tokens
			group = binary.BigEndian.AppendUint16(group, uint16(bestOff<<4|(bestLen-2))) // #nosec G115 -- 12+4 bits
			for _, c := range replay(bestOff, bestLen) {
				put(c)
			}
			i += bestLen
		} else {
			group = append(group, raw[i])
			put(raw[i])
			i++
		}
		if tokens++; tokens == 8 {
			flush()
		}
	}
	// The end marker: a reference to the write position.
	ctrl |= 1 << tokens
	group = binary.BigEndian.AppendUint16(group, uint16(wpos<<4)) // #nosec G115 -- 12 bits
	flush()
	return lzfuStream(lzfuCompressed, uint32(len(raw)), body) // #nosec G115 -- test data
}

func lzfuStream(typ, rawSize uint32, body []byte) []byte {
	crc := uint32(0)
	if typ == lzfuCompressed {
		crc = lzfuCRC(body)
	}
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(body)+12)) // #nosec G115 -- test data
	b = binary.LittleEndian.AppendUint32(b, rawSize)
	b = binary.LittleEndian.AppendUint32(b, typ)
	b = binary.LittleEndian.AppendUint32(b, crc)
	return append(b, body...)
}

func lzfuDecode(t *testing.T, b []byte) (string, error) {
	t.Helper()
	r, err := newLZFuReader(b)
	if err != nil {
		return "", err
	}
	out, err := io.ReadAll(r)
	return string(out), err
}

// A compressed stream from MS-OXRTFCP's examples (section 3).
func TestLZFu_SpecExample(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1a0000001c0000004c5a4675e2d44b51410004205758595a0d6e7d010eb0", `{\rtf1 WXYZWXYZWXYZWXYZWXYZ}`},
	} {
		b, err := hex.DecodeString(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := lzfuDecode(t, b)
		if err != nil || got != tc.want {
			t.Errorf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestLZFu_RoundTrip(t *testing.T) {
	for _, raw := range []string{
		"",
		`{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Arial;}}\pard card 4111 1111 1111 1111\par}`,
		strings.Repeat("abcabcabc", 1000), // references across the dictionary's wrap
		strings.Repeat("x", 40),           // a reference overlapping what it writes
	} {
		got, err := lzfuDecode(t, lzfuCompress([]byte(raw)))
		if err != nil || got != raw {
			t.Fatalf("round trip of %d bytes: %d bytes, %v", len(raw), len(got), err)
		}
	}
	if got, err := lzfuDecode(t, lzfuStream(lzfuRaw, 5, []byte("hello, padded"))); err != nil || got != "hello" {
		t.Fatalf("uncompressed: %q %v", got, err)
	}
}

func TestLZFu_Corrupt(t *testing.T) {
	good := lzfuCompress([]byte(`{\rtf1 hello world, hello world}`))
	badCRC := append([]byte(nil), good...)
	badCRC[len(badCRC)-1] ^= 0xff
	shortComp := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(shortComp[0:], 2)
	for name, b := range map[string][]byte{
		"short header":   good[:10],
		"bad crc":        badCRC,
		"comp size":      shortComp,
		"past the end":   good[:len(good)-3],
		"unknown type":   lzfuStream(0x12345678, 0, nil),
		"raw size large": lzfuStream(lzfuRaw, 100, []byte("abc")),
	} {
		if _, err := newLZFuReader(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Data that ends without the end marker: what decoded is kept, then an
	// error.
	trunc := lzfuStream(lzfuCompressed, 100, []byte{0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'})
	if got, err := lzfuDecode(t, trunc); got != "abcdefgh" || err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %q %v", got, err)
	}
	// A literal or a reference cut short.
	for _, body := range [][]byte{{0x00}, {0x01, 0x10}} {
		if _, err := lzfuDecode(t, lzfuStream(lzfuCompressed, 10, body)); err != io.ErrUnexpectedEOF {
			t.Errorf("cut %x: %v", body, err)
		}
	}
	// The raw size caps the output, whatever the stream says.
	capped := lzfuCompress([]byte("0123456789"))
	binary.LittleEndian.PutUint32(capped[4:], 4)
	if got, err := lzfuDecode(t, capped); got != "0123" || err != nil {
		t.Fatalf("capped: %q %v", got, err)
	}
}

func TestScan_OutlookMessageCompressedRTF(t *testing.T) {
	s := newTestScanner(t)
	rtfBody := func(rtf string) [2]string {
		return [2]string{"__substg1.0_10090102", string(lzfuCompress([]byte(rtf)))}
	}
	html := `{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}` +
		`{\*\htmltag19 <html>}{\*\htmltag34 <head><style>p{x:y}</style></head>}{\*\htmltag50 <body>}` +
		`\htmlrtf {\htmlrtf0 {\*\htmltag64 <p>}Card ` + testCard + `{\*\htmltag72 </p>}}\htmlrtf0 {\*\htmltag58 </body></html>}}`
	bad := []byte(rtfBody(`{\rtf1 card ` + testCard + `}`)[1])
	bad[len(bad)-1] ^= 0xff
	for _, tc := range []struct {
		name   string
		data   []byte
		status string
		cards  int
	}{
		{"plain RTF", msgFile(t, rtfBody(`{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}\pard card `+testCard+`\par}`)), StatusScanned, 1},
		{"HTML in RTF", msgFile(t, rtfBody(html)), StatusScanned, 1},
		{"uncompressed", msgFile(t, [2]string{"__substg1.0_10090102",
			string(lzfuStream(lzfuRaw, uint32(len(`{\rtf1 `+testCard+`}`)), []byte(`{\rtf1 `+testCard+`}`)))}), StatusScanned, 1},
		{"corrupt", msgFile(t, [2]string{"__substg1.0_10090102", string(bad)}), StatusTruncated, 0},
		{"not LZFu", msgFile(t, [2]string{"__substg1.0_10090102", "LZFu..."}), StatusTruncated, 0},
		{"plain body wins", msgFile(t, [2]string{"__substg1.0_1000001F", u16("nothing")}, rtfBody(`{\rtf1 `+testCard+`}`)), StatusScanned, 0},
	} {
		res := scanBytes(t, s, tc.data)
		if res.Status != tc.status || count(res.Findings, "pii.credit_card") != tc.cards {
			t.Errorf("%s: %q %+v", tc.name, res.Status, res.Findings)
		}
	}
}

func FuzzLZFu(f *testing.F) {
	f.Add(lzfuCompress([]byte(`{\rtf1\ansi hello hello hello}`)))
	f.Add(lzfuStream(lzfuRaw, 3, []byte("abc")))
	f.Add(lzfuStream(lzfuCompressed, 1<<30, []byte{0xff, 0xff, 0xff}))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := newLZFuReader(b)
		if err != nil {
			return
		}
		n, _ := io.Copy(io.Discard, r)
		if raw := int64(binary.LittleEndian.Uint32(b[4:])); n > raw {
			t.Fatalf("%d bytes past the raw size %d", n, raw)
		}
	})
}
