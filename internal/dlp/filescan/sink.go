package filescan

import (
	"bytes"
	"context"
	"errors"
	"unicode/utf8"

	"sentinelgo/internal/dlp/detect"
)

// errTextLimit stops an extractor once the text budget is spent.
var errTextLimit = errors.New("text limit reached")

// scanState is shared by a file and every archive entry inside it.
type scanState struct {
	s   *Scanner
	ctx context.Context

	textLeft    int   // extracted text that may still be scanned
	archiveLeft int64 // bytes that may still be decompressed
	entriesLeft int
	entries     []Entry
}

// textSink receives one document's extracted text and scans it in chunks.
//
// Chunk boundaries: a chunk is cut at a newline (or else a space) in the
// first half of its overlap window, and the next chunk starts at the cut. A
// chunk keeps only matches that start before the cut; matches at or after it
// are found again, whole, by the next chunk. So no match is counted twice,
// and a match shorter than half the overlap is never split.
type textSink struct {
	st        *scanState
	buf       []byte
	base      int // offset of buf[0] in the document's text
	findings  []detect.Finding
	idx       map[[2]string]int
	truncated bool
}

func newSink(st *scanState) *textSink {
	return &textSink{st: st, idx: map[[2]string]int{}}
}

// WriteString adds text. It returns errTextLimit once the budget is spent
// (what fits is kept) and the context's error once it is done.
func (t *textSink) WriteString(s string) error {
	if err := t.st.ctx.Err(); err != nil {
		return err
	}
	if t.truncated {
		return errTextLimit
	}
	if len(s) > t.st.textLeft {
		s = s[:t.st.textLeft]
		if i := lastRuneStart(s); i < len(s) && !utf8.FullRuneInString(s[i:]) {
			s = s[:i] // don't keep half a character
		}
		t.truncated = true
	}
	t.st.textLeft -= len(s)
	t.buf = append(t.buf, s...)
	for len(t.buf) >= t.st.s.chunk {
		t.scanChunk(false)
	}
	if t.truncated {
		return errTextLimit
	}
	return nil
}

func lastRuneStart(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if utf8.RuneStart(s[i]) {
			return i
		}
	}
	return 0
}

// finish scans what is left and returns the document's findings.
func (t *textSink) finish() []detect.Finding {
	if len(t.buf) > 0 {
		t.scanChunk(true)
	}
	return t.findings
}

func (t *textSink) scanChunk(final bool) {
	eng := t.st.s.engine
	n := len(t.buf)
	cut := n
	if !final {
		n = t.st.s.chunk
		cut = t.cutPoint(t.buf[:n])
	}
	if eng != nil {
		res := eng.Scan(string(t.buf[:n]))
		for _, f := range res.Findings {
			t.add(f, cut)
		}
	}
	if final {
		t.base += len(t.buf)
		t.buf = t.buf[:0]
		return
	}
	rest := copy(t.buf, t.buf[cut:])
	t.buf = t.buf[:rest]
	t.base += cut
}

// cutPoint picks where the next chunk starts: the last newline, else the last
// space or tab, in [n-overlap, n-overlap/2], else n-overlap; always at the
// start of a rune.
func (t *textSink) cutPoint(chunk []byte) int {
	n, ov := len(chunk), t.st.s.overlap
	lo, hi := max(n-ov, 1), max(n-ov/2, 1)
	win := chunk[lo:hi]
	cut := lo
	if i := bytes.LastIndexByte(win, '\n'); i >= 0 {
		cut = lo + i + 1
	} else if i := bytes.LastIndexAny(win, " \t"); i >= 0 {
		cut = lo + i + 1
	}
	for cut > 1 && !utf8.RuneStart(chunk[cut]) {
		cut--
	}
	return cut
}

// add merges f's matches that start before cut into the document's findings,
// with offsets moved into the document's text.
func (t *textSink) add(f detect.Finding, cut int) {
	var offs [][2]int
	for _, o := range f.Offsets {
		if o[0] < cut {
			offs = append(offs, [2]int{o[0] + t.base, o[1] + t.base})
		}
	}
	if len(offs) == 0 {
		return
	}
	key := [2]string{f.DetectorID, f.RuleID}
	i, ok := t.idx[key]
	if !ok {
		f.Count, f.Offsets = 0, nil
		t.findings = append(t.findings, f)
		i = len(t.findings) - 1
		t.idx[key] = i
	}
	t.findings[i].Count += len(offs)
	t.findings[i].Offsets = append(t.findings[i].Offsets, offs...)
}

// docResult is one document's (or archive's) outcome.
type docResult struct {
	status   string
	typ      string
	findings []detect.Finding
	labels   []string
}

// finishDoc turns an extractor's error and the sink into a docResult.
func (st *scanState) finishDoc(typ string, sink *textSink, err error) docResult {
	d := docResult{typ: typ, status: StatusScanned}
	if sink != nil {
		d.findings = sink.finish()
		if sink.truncated {
			d.status = StatusTruncated
		}
	}
	switch {
	case err == nil, errors.Is(err, errTextLimit):
	default:
		d.status = worse(d.status, statusFor(st.ctx, err))
	}
	return d
}
