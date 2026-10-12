package task

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Task notes are capped so a verbose script (msiexec with logging, apt-get)
// can't bloat the agent_update_task RPC or the database row. The end of the
// output is what explains a failure, so most of the budget goes to the tail.
const (
	noteHeadBytes = 8 << 10
	noteTailBytes = 56 << 10
	maxNoteBytes  = noteHeadBytes + noteTailBytes
)

// rebootMarker is the line a rendered install script prints when the
// installer asked for a reboot (contract §7). It must survive truncation.
const rebootMarker = "SENTINEL_REBOOT_REQUIRED"

// outputBuffer collects a script's output in bounded memory: the first
// noteHeadBytes, a ring of the last noteTailBytes, and the count of bytes
// dropped between them. It also notices the reboot marker anywhere in the
// stream, even in the dropped middle or split across writes. It is safe for
// concurrent use, so it can be both Stdout and Stderr of a command.
type outputBuffer struct {
	mu      sync.Mutex
	head    []byte
	tail    []byte // ring buffer of up to noteTailBytes once full
	tailPos int    // next write position in tail once it is full
	total   int64
	carry   []byte // last len(rebootMarker)-1 bytes, for split markers
	sawMark bool
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.scanMarker(p)
	b.total += int64(len(p))
	n := len(p)

	if room := noteHeadBytes - len(b.head); room > 0 {
		take := min(room, len(p))
		b.head = append(b.head, p[:take]...)
		p = p[take:]
	}
	if len(p) == 0 {
		return n, nil
	}
	if len(p) >= noteTailBytes {
		// A single write that fills the ring: keep only its end.
		b.tail = append(b.tail[:0], p[len(p)-noteTailBytes:]...)
		b.tailPos = 0
		return n, nil
	}
	for len(p) > 0 {
		if len(b.tail) < noteTailBytes {
			take := min(noteTailBytes-len(b.tail), len(p))
			b.tail = append(b.tail, p[:take]...)
			p = p[take:]
			continue
		}
		c := copy(b.tail[b.tailPos:], p)
		b.tailPos = (b.tailPos + c) % noteTailBytes
		p = p[c:]
	}
	return n, nil
}

func (b *outputBuffer) scanMarker(p []byte) {
	if b.sawMark {
		return
	}
	const k = len(rebootMarker) - 1
	// Check p itself, then the seam between the previous write and p.
	seam := append(append([]byte(nil), b.carry...), p[:min(k, len(p))]...)
	if bytes.Contains(p, []byte(rebootMarker)) || bytes.Contains(seam, []byte(rebootMarker)) {
		b.sawMark = true
		b.carry = nil
		return
	}
	if len(p) >= k {
		b.carry = append(b.carry[:0], p[len(p)-k:]...)
		return
	}
	b.carry = append(b.carry, p...)
	if len(b.carry) > k {
		b.carry = b.carry[len(b.carry)-k:]
	}
}

// String returns the bounded output: the whole stream if it fit, otherwise
// head + a truncation note + tail, plus the reboot marker line if it was cut.
func (b *outputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	tail := b.tail
	if len(b.tail) == noteTailBytes && b.tailPos != 0 {
		tail = append(append([]byte{}, b.tail[b.tailPos:]...), b.tail[:b.tailPos]...)
	}
	dropped := b.total - int64(len(b.head)) - int64(len(tail))

	var s strings.Builder
	s.Write(b.head)
	if dropped > 0 {
		fmt.Fprintf(&s, "\n…[truncated %d bytes]…\n", dropped)
	}
	s.Write(tail)
	out := strings.ToValidUTF8(s.String(), "�")
	if b.sawMark && !strings.Contains(out, rebootMarker) {
		out += "\n" + rebootMarker
	}
	return out
}

// capNote bounds a task note to maxNoteBytes (plus the truncation and
// reboot-marker lines) the same way outputBuffer bounds script output.
func capNote(note string) string {
	if len(note) <= maxNoteBytes {
		return note
	}
	var b outputBuffer
	_, _ = b.Write([]byte(note))
	return b.String()
}

// runBounded runs cmd with stdout and stderr interleaved into one
// outputBuffer, like CombinedOutput but without holding all of it in memory.
func runBounded(cmd *exec.Cmd) (string, error) {
	var out outputBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
