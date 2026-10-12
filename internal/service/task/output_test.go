package task

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestOutputBuffer_SmallOutputUnchanged(t *testing.T) {
	var b outputBuffer
	_, _ = b.Write([]byte("hello "))
	_, _ = b.Write([]byte("world"))
	if got := b.String(); got != "hello world" {
		t.Errorf("String() = %q", got)
	}
}

func TestOutputBuffer_ExactlyAtCapUnchanged(t *testing.T) {
	in := bytes.Repeat([]byte("x"), maxNoteBytes)
	var b outputBuffer
	_, _ = b.Write(in)
	if got := b.String(); got != string(in) {
		t.Errorf("len = %d, want the full %d bytes untouched", len(got), len(in))
	}
}

// numbered makes n bytes of 16-byte records that each name their own offset,
// so any slice of it shows where it came from.
func numbered(n int) []byte {
	var buf bytes.Buffer
	for i := 0; buf.Len() < n; i++ {
		fmt.Fprintf(&buf, "%15d\n", i*16)
	}
	return buf.Bytes()[:n]
}

func checkHeadTail(t *testing.T, got string, in []byte) {
	t.Helper()
	if !strings.HasPrefix(got, string(in[:noteHeadBytes])) {
		t.Error("output does not start with the first 8 KiB")
	}
	if !strings.HasSuffix(got, string(in[len(in)-noteTailBytes:])) {
		t.Error("output does not end with the last 56 KiB")
	}
	want := "\n…[truncated " + strconv.Itoa(len(in)-maxNoteBytes) + " bytes]…\n"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q", want)
	}
}

func TestOutputBuffer_SingleHugeWrite(t *testing.T) {
	in := numbered(5 << 20)
	var b outputBuffer
	n, err := b.Write(in)
	if n != len(in) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	got := b.String()
	if len(got) > maxNoteBytes+64 {
		t.Errorf("len = %d, want about %d", len(got), maxNoteBytes)
	}
	checkHeadTail(t, got, in)
}

func TestOutputBuffer_ManySmallWrites(t *testing.T) {
	in := numbered(1<<20 + 12345)
	var b outputBuffer
	for off := 0; off < len(in); off += 7 {
		_, _ = b.Write(in[off:min(off+7, len(in))])
	}
	checkHeadTail(t, b.String(), in)
}

func TestOutputBuffer_Boundaries(t *testing.T) {
	// Sizes around the head and head+tail boundaries, written in chunks that
	// don't line up with either.
	sizes := []int{noteHeadBytes - 1, noteHeadBytes, noteHeadBytes + 1, maxNoteBytes - 1, maxNoteBytes + 1, maxNoteBytes + noteTailBytes, 3*maxNoteBytes + 5}
	chunks := []int{1, 1000, noteTailBytes - 1, noteTailBytes, noteTailBytes + 1}
	for _, size := range sizes {
		for _, chunk := range chunks {
			in := numbered(size)
			var b outputBuffer
			for off := 0; off < len(in); off += chunk {
				_, _ = b.Write(in[off:min(off+chunk, len(in))])
			}
			got := b.String()
			if size <= maxNoteBytes {
				if got != string(in) {
					t.Errorf("size %d chunk %d: output changed although it fit", size, chunk)
				}
				continue
			}
			checkHeadTail(t, got, in)
		}
	}
}

func TestOutputBuffer_RebootMarkerInDroppedMiddleKept(t *testing.T) {
	body := numbered(5 << 20)
	mid := len(body) / 2
	in := append(append(append([]byte{}, body[:mid]...), "\n"+rebootMarker+"\n"...), body[mid:]...)

	// Split the marker across two writes.
	split := mid + 10
	var b outputBuffer
	_, _ = b.Write(in[:split])
	_, _ = b.Write(in[split:])

	got := b.String()
	if !strings.HasSuffix(got, "\n"+rebootMarker) {
		t.Errorf("reboot marker not appended; output ends %q", got[len(got)-40:])
	}
	if len(got) > maxNoteBytes+128 {
		t.Errorf("len = %d", len(got))
	}
}

func TestOutputBuffer_RebootMarkerInTailNotDuplicated(t *testing.T) {
	in := append(numbered(1<<20), rebootMarker+"\n"...)
	var b outputBuffer
	_, _ = b.Write(in)
	if n := strings.Count(b.String(), rebootMarker); n != 1 {
		t.Errorf("marker appears %d times, want 1", n)
	}
}

func TestOutputBuffer_MarkerWrittenOneByteAtATime(t *testing.T) {
	var b outputBuffer
	_, _ = b.Write(numbered(maxNoteBytes))
	for _, c := range []byte("x" + rebootMarker + "y") {
		_, _ = b.Write([]byte{c})
	}
	_, _ = b.Write(numbered(2 * maxNoteBytes))
	if got := b.String(); !strings.HasSuffix(got, "\n"+rebootMarker) {
		t.Error("marker written one byte at a time was not detected")
	}
}

func TestOutputBuffer_NoMarkerNoAppend(t *testing.T) {
	var b outputBuffer
	_, _ = b.Write(numbered(1 << 20))
	_, _ = b.Write([]byte("SENTINEL_REBOOT_REQUIRE"))
	if strings.Contains(b.String(), rebootMarker) {
		t.Error("a partial marker was reported as the marker")
	}
}

func TestOutputBuffer_ConcurrentWriters(t *testing.T) {
	var b outputBuffer
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				_, _ = b.Write([]byte("0123456789abcdef"))
			}
		}()
	}
	wg.Wait()
	if b.total != 8*1000*16 {
		t.Errorf("total = %d", b.total)
	}
	if got := b.String(); len(got) > maxNoteBytes+64 {
		t.Errorf("len = %d", len(got))
	}
}

func TestCapNote(t *testing.T) {
	if got := capNote("short"); got != "short" {
		t.Errorf("capNote(short) = %q", got)
	}
	long := string(numbered(5<<20)) + "\n" + rebootMarker + "\n" + string(numbered(1<<20))
	got := capNote(long)
	if len(got) > maxNoteBytes+128 {
		t.Errorf("len = %d", len(got))
	}
	if !strings.HasPrefix(got, long[:noteHeadBytes]) || !strings.HasSuffix(got, rebootMarker) {
		t.Error("capNote lost the head or the reboot marker")
	}
}

func TestCapNote_SplitRuneRepaired(t *testing.T) {
	// A 3-byte rune straddling the head boundary.
	in := strings.Repeat("a", noteHeadBytes-1) + "€" + strings.Repeat("b", maxNoteBytes)
	got := capNote(in)
	if !utf8.ValidString(got) {
		t.Error("capped note is not valid UTF-8")
	}
}
