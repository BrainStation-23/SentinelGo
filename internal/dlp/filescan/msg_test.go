package filescan

import (
	"encoding/binary"
	"strings"
	"testing"
)

func u16(s string) string { return string(utf16le(s)) }

// msgFile builds an Outlook message: extra streams are added as given.
func msgFile(t testing.TB, extra ...[2]string) []byte {
	t.Helper()
	streams := append([][2]string{{"__properties_version1.0", "props"}}, extra...)
	return buildCFB(t, streams...)
}

func TestScan_OutlookMessage(t *testing.T) {
	s := newTestScanner(t)
	data := msgFile(t,
		[2]string{"__substg1.0_0037001F", u16("Quarterly numbers")},
		[2]string{"__substg1.0_1000001F", u16("Hi Bob, the card is " + testCard + "\x00")},
		[2]string{"__recip_version1.0_#00000000/__substg1.0_3001001F", u16("Bob")},
		[2]string{"__recip_version1.0_#00000000/__substg1.0_39FE001F", u16("bob@example.com")},
		[2]string{"__attach_version1.0_#00000000/__substg1.0_3707001F", u16("keys.txt")},
		[2]string{"__attach_version1.0_#00000000/__substg1.0_37010102", "the TOPSECRET keys"},
		[2]string{"__attach_version1.0_#00000001/__substg1.0_3707001F", u16("Fwd: plan.msg")},
		[2]string{"__attach_version1.0_#00000001/__substg1.0_3701000D/__properties_version1.0", "props"},
		[2]string{"__attach_version1.0_#00000001/__substg1.0_3701000D/__substg1.0_1000001F", u16("nested TOPSECRET plan")},
		[2]string{"__attach_version1.0_#00000002/__substg1.0_3707001F", u16("clean.txt")},
		[2]string{"__attach_version1.0_#00000002/__substg1.0_37010102", "nothing here"},
	)
	res := scanBytes(t, s, data)
	if res.Status != StatusScanned || res.DetectedType != "ole.msg" || count(res.Findings, "pii.credit_card") != 1 {
		t.Fatalf("message: %q %q %+v", res.Status, res.DetectedType, res.Findings)
	}
	names := map[string]Entry{}
	for _, e := range res.Entries {
		names[e.Name] = e
	}
	if e, ok := names["keys.txt"]; !ok || count(e.Findings, "kw") != 1 {
		t.Errorf("attachment: %+v", res.Entries)
	}
	if e, ok := names["Fwd: plan.msg"]; !ok || e.DetectedType != "ole.msg" || count(e.Findings, "kw") != 1 {
		t.Errorf("attached message: %+v", res.Entries)
	}
	if _, ok := names["clean.txt"]; ok {
		t.Errorf("clean attachment listed: %+v", res.Entries)
	}
}

func TestScan_OutlookMessageBodies(t *testing.T) {
	s := newTestScanner(t)
	for _, tc := range []struct {
		name   string
		data   []byte
		status string
		cards  int
	}{
		{"html body only", msgFile(t, [2]string{"__substg1.0_10130102",
			"<html><head><style>.c{}</style></head><body><p>Card&nbsp;" + testCard + "</p><script>x()</script></body></html>"}), StatusScanned, 1},
		{"8-bit body", msgFile(t, [2]string{"__substg1.0_1000001E", "card " + testCard}), StatusScanned, 1},
		{"compressed RTF only", msgFile(t, [2]string{"__substg1.0_10090102", "LZFu..."}), StatusTruncated, 0},
		{"S/MIME encrypted", msgFile(t, [2]string{"__substg1.0_001A001F", u16("IPM.Note.SMIME")}), Unscannable(ReasonEncrypted), 0},
		{"S/MIME signed is read", msgFile(t, [2]string{"__substg1.0_001A001F", u16("IPM.Note.SMIME.MultipartSigned")},
			[2]string{"__substg1.0_1000001F", u16(testCard)}), StatusScanned, 1},
	} {
		res := scanBytes(t, s, tc.data)
		if res.Status != tc.status || count(res.Findings, "pii.credit_card") != tc.cards {
			t.Errorf("%s: %q %+v", tc.name, res.Status, res.Findings)
		}
	}
}

func TestHTMLText(t *testing.T) {
	got := htmlText([]byte("<style>p{color:red}</style><p>a&amp;b</p><div>c<br>d</div>\xe9"))
	if strings.Contains(got, "color") || !strings.Contains(got, "a&b") || !strings.Contains(got, "c\nd") || !strings.Contains(got, "é") {
		t.Fatalf("%q", got)
	}
}

// Excel 5/95 (BIFF5): text cells as LABEL and RSTRING with 8-bit strings,
// numbers as NUMBER.
func TestScan_Excel5(t *testing.T) {
	rec := func(typ uint16, data []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, typ)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	cellHdr := make([]byte, 6)
	label := func(s string) []byte {
		d := append(append([]byte{}, cellHdr...), binary.LittleEndian.AppendUint16(nil, uint16(len(s)))...)
		return append(d, s...)
	}
	var book []byte
	book = append(book, rec(xlsLabel, label("card "+testCard))...)
	book = append(book, rec(xlsRString, append(label("TOPSECRET"), 0, 0))...)
	num := append(append([]byte{}, cellHdr...), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(num[6:], 0x4330000000000000) // 2^52: a whole number
	book = append(book, rec(xlsNumber, num)...)
	res := scanBytes(t, newTestScanner(t), buildCFB(t, [2]string{"Book", string(book)}))
	if res.Status != StatusScanned || res.DetectedType != "ole.xls5" || count(res.Findings, "pii.credit_card") != 1 || count(res.Findings, "kw") != 1 {
		t.Fatalf("%q %q %+v", res.Status, res.DetectedType, res.Findings)
	}
	pass := rec(xlsFilePass, []byte{0, 0})
	if res := scanBytes(t, newTestScanner(t), buildCFB(t, [2]string{"Book", string(pass)})); res.Status != Unscannable(ReasonPasswordProtected) {
		t.Fatalf("password: %q", res.Status)
	}
	if _, _, ok := readBIFF5String([]byte{5, 0, 'a'}); ok {
		t.Fatal("short string read")
	}
}
