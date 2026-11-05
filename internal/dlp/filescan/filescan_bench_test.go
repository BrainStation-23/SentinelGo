package filescan

// Benchmarks per format and size (#327, #340). The corpus is synthetic:
// never real customer files.
//
// go test -run='^$' -bench=. -benchmem ./internal/dlp/filescan/

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"sentinelgo/internal/dlp/policy"
)

// benchText is size bytes of CSV-like text with a few findings.
func benchText(size int) string {
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "%d,customer-%d,city-%d,%d.%02d\n", i, i*7, i%97, i%1000, i%100)
		if i%5000 == 0 {
			b.WriteString("x," + testCard + ",TOPSECRET\n")
		}
	}
	return b.String()
}

func benchDocx(b *testing.B, size int) []byte {
	var body strings.Builder
	for _, line := range strings.Split(benchText(size), "\n") {
		body.WriteString("<w:p><w:r><w:t>" + line + "</w:t></w:r></w:p>")
	}
	return docx(b, body.String())
}

func benchXLSX(b *testing.B, rows int) []byte {
	var sheet strings.Builder
	sheet.WriteString("<worksheet><sheetData>")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&sheet, `<row r="%d"><c><v>%d</v></c><c t="s"><v>%d</v></c><c><v>%d.5</v></c></row>`, i+1, i, i%100, i*3)
	}
	sheet.WriteString("</sheetData></worksheet>")
	return zipOf(b,
		[2]string{"[Content_Types].xml", `<Types/>`},
		[2]string{"xl/workbook.xml", `<workbook/>`},
		[2]string{"xl/sharedStrings.xml", "<sst>" + strings.Repeat("<si><t>customer name</t></si>", 100) + "</sst>"},
		[2]string{"xl/worksheets/sheet1.xml", sheet.String()},
	)
}

func benchScan(b *testing.B, data []byte) {
	s := New(testEngine(b), LimitsFrom(policy.FilesModule{MaxFileBytes: policy.MaxFileBytesLimit, MaxTextBytes: policy.MaxTextBytesLimit, ScanTimeoutMs: 60000}), b.TempDir())
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := s.Scan(context.Background(), Source{Size: int64(len(data))}, bytes.NewReader(data))
		if res.Status != StatusScanned && res.Status != StatusTruncated {
			b.Fatalf("status %q", res.Status)
		}
	}
}

func BenchmarkScan_Text100K(b *testing.B) { benchScan(b, []byte(benchText(100<<10))) }
func BenchmarkScan_Text4M(b *testing.B)   { benchScan(b, []byte(benchText(4<<20))) }
func BenchmarkScan_UTF16_1M(b *testing.B) {
	benchScan(b, encodeUTF16(benchText(1<<20), false, true))
}
func BenchmarkScan_Docx1M(b *testing.B)      { benchScan(b, benchDocx(b, 1<<20)) }
func BenchmarkScan_XLSX50kRows(b *testing.B) { benchScan(b, benchXLSX(b, 50000)) }
func BenchmarkScan_Zip100Files(b *testing.B) { benchScan(b, benchZip(b, 100, 10<<10)) }
func BenchmarkScan_PDF100Pages(b *testing.B) { benchScan(b, benchPDF(100, 4<<10)) }

// benchPDF is a PDF of pages pages, each a Flate content stream showing
// about each bytes of text, one line per Tj.
func benchPDF(pages, each int) []byte {
	p := newPDF().obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	var kids strings.Builder
	for i := 0; i < pages; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", 10+2*i)
	}
	p.obj(2, "<< /Type /Pages /Count "+fmt.Sprint(pages)+" /Kids ["+kids.String()+"] /Resources << /Font << /F1 3 0 R >> >> >>")
	p.obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	for i := 0; i < pages; i++ {
		var c strings.Builder
		c.WriteString("BT /F1 10 Tf 72 720 Td 12 TL\n")
		for _, line := range strings.Split(benchText(each), "\n") {
			fmt.Fprintf(&c, "(%s) '\n", line)
		}
		c.WriteString("ET")
		p.obj(10+2*i, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /Contents %d 0 R >>", 11+2*i))
		p.stream(11+2*i, "", []byte(c.String()), true)
	}
	return p.bytes("/Root 1 0 R")
}

func benchZip(b *testing.B, n, each int) []byte {
	var es [][2]string
	for i := 0; i < n; i++ {
		es = append(es, [2]string{fmt.Sprintf("dir/file%d.csv", i), benchText(each)})
	}
	return zipOf(b, es...)
}

func BenchmarkSniff(b *testing.B) {
	head := []byte(benchText(sniffBytes))
	for i := 0; i < b.N; i++ {
		sniff(head)
	}
}
