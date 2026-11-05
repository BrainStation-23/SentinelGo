package filescan

// Fuzz targets for the parsers (#327): every extractor reads files an
// attacker controls. They must never panic, hang or exceed their limits.
//
// To fuzz: go test -run='^$' -fuzz='^FuzzScan$' -fuzztime=1m ./internal/dlp/filescan/
//          go test -run='^$' -fuzz='^FuzzRTF$' -fuzztime=1m ./internal/dlp/filescan/

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func FuzzScan(f *testing.F) {
	f.Add([]byte("plain text " + testCard))
	f.Add(encodeUTF16("utf16 TOPSECRET", false, true))
	f.Add(docx(f, `<w:p><w:r><w:t>`+testCard+`</w:t></w:r></w:p>`))
	f.Add(zipOf(f, [2]string{"a.txt", "TOPSECRET"}, [2]string{"b.zip", string(zipOf(f, [2]string{"c.txt", "x"}))}))
	f.Add(zipOf(f, [2]string{"mimetype", "application/vnd.oasis.opendocument.text"}, [2]string{"content.xml", "<text:p>x</text:p>"}))
	f.Add([]byte(`{\rtf1 {\fonttbl x} card \'41\u65? TOPSECRET\par}`))
	f.Add(cfbWith("EncryptedPackage"))
	f.Add([]byte("%PDF-1.4"))
	f.Add(simplePDF("BT /F1 12 Tf ("+testCard+") Tj [(TOP)-300(SECRET)] TJ ET", true))
	f.Add(simplePDF("BT /F1 12 Tf <0013001400150016> Tj ET", false))
	f.Add(buildCFB(f, wordDoc("Card "+testCard+"\r", "TOPSECRET", 0)...))
	f.Add(buildCFB(f, [2]string{"Workbook", workbook()}))
	f.Add(msgFile(f, [2]string{"__substg1.0_1000001F", u16(testCard)}, [2]string{"__attach_version1.0_#00000000/__substg1.0_37010102", "TOPSECRET"}))
	f.Add(buildCFB(f, [2]string{"Book", "\x04\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x03\x00abc"}))
	f.Add(buildCFB(f, [2]string{"PowerPoint Document", powerPoint()}))
	f.Add(buildCFB(f, [2]string{"\x01Ole10Native", ole10Native("a.txt", []byte("TOPSECRET"))}))
	eng := testEngine(f)
	lim := testLimits()
	lim.MaxFileBytes, lim.MaxTextBytes, lim.Timeout = 1<<20, 64<<10, 2*time.Second
	lim.MaxArchiveBytes = 4 << 20
	f.Fuzz(func(t *testing.T, data []byte) {
		s := New(eng, lim, "")
		s.chunk, s.overlap = 512, 64
		res := s.Scan(context.Background(), Source{Size: int64(len(data))}, bytes.NewReader(data))
		if res.Status == "" {
			t.Fatal("no status")
		}
		if res.TextBytes > lim.MaxTextBytes {
			t.Fatalf("scanned %d bytes of text, limit %d", res.TextBytes, lim.MaxTextBytes)
		}
		if len(res.Entries) > lim.MaxEntries {
			t.Fatalf("%d entries, limit %d", len(res.Entries), lim.MaxEntries)
		}
	})
}

func FuzzRTF(f *testing.F) {
	f.Add(`{\rtf1\ansi{\fonttbl{\f0 Arial;}}\pard Caf\'e9 \u8364? \bin3 abc{\*\x y}\par}`)
	f.Add(`{\rtf1 \uc2\u-3913?? \'zz \` + "\x00")
	f.Fuzz(func(t *testing.T, in string) {
		st := &scanState{s: &Scanner{chunk: 256, overlap: 32}, ctx: context.Background(), textLeft: 1 << 20}
		sink := newSink(st)
		_ = extractRTF(strings.NewReader(in), sink)
		if st.textLeft < 0 {
			t.Fatal("text budget overrun")
		}
	})
}
