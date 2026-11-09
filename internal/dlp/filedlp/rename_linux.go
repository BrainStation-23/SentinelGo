package filedlp

// Saves through a temporary file (#337). Office suites and most editors save
// by writing a temp file next to the document and renaming it onto the
// destination (LibreOffice "lu…tmp", MS Office "~WRL….tmp" and 8-hex names,
// GIO ".goutputstream-…"). FAN_CLOSE_WRITE reports the temp file; its
// descriptor follows the rename, but the name read when the event arrives is
// usually still the temp one, so the event, the extension a policy matches
// and a quarantine would all see the wrong file.
//
// A close-write whose name looks like a temp file is therefore held for a
// moment and its name read again until it changes: renamed (decided under
// the new name), deleted (dropped: nothing reached the device), or still
// the same when the hold ends (decided as it is). Nothing is ever skipped
// because of its name: a held file is decided like any other, just later.

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Tuning (variables for tests).
var (
	renameHold = 2 * time.Second       // how long a temp-named file waits for its rename
	renamePoll = 50 * time.Millisecond // how often held names are read again
)

// maxHeld bounds the files held at once; past it, a temp-named file is
// decided at once under the name it has.
const maxHeld = 64

// deletedSuffix ends the name /proc gives a descriptor whose file was unlinked.
const deletedSuffix = " (deleted)"

type heldRequest struct {
	r     Request
	until time.Time
}

// renameLoop owns the held files: it reads their names every renamePoll and
// queues each once it was renamed or its hold ended. On stop it closes them.
func (e *linuxEnforcer) renameLoop(ctx context.Context, held <-chan Request, queue chan<- Request) {
	defer e.wg.Done()
	var pending []heldRequest
	t := time.NewTicker(renamePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, h := range pending {
				_ = h.r.File.Close()
			}
			return
		case r := <-held:
			pending = append(pending, heldRequest{r: r, until: time.Now().Add(renameHold)})
		case now := <-t.C:
			kept := pending[:0]
			for _, h := range pending {
				if !e.settle(&h.r, now.After(h.until), queue) {
					kept = append(kept, h)
				}
			}
			clear(pending[len(kept):])
			pending = kept
		}
	}
}

// settle reads a held file's name again. It returns true when the file is
// done with: queued under its new name (or its old one once expired), or
// dropped because it was deleted.
func (e *linuxEnforcer) settle(r *Request, expired bool, queue chan<- Request) bool {
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(r.File.Fd()))) // #nosec G115 -- a descriptor
	switch {
	case err != nil:
		// Can't tell: decide it under the name it had.
	case strings.HasSuffix(path, deletedSuffix):
		var st unix.Stat_t
		if unix.Fstat(int(r.File.Fd()), &st) == nil && st.Nlink == 0 { // #nosec G115 -- a descriptor
			_ = r.File.Close() // a temp file removed: nothing of it is on the device
			return true
		}
		// Unlinked under this name but linked under another: decide it.
	case path != r.Path:
		r.Path = path
		if d, ok := e.destinationOf(path); ok {
			r.Dest = d
		}
	case !expired:
		return false
	}
	e.enqueue(*r, queue)
	return true
}

// hold queues a temp-named file to wait for its rename, or returns false
// when too many already wait.
func hold(r Request, held chan<- Request) bool {
	select {
	case held <- r:
		return true
	default:
		return false
	}
}

// enqueue queues a request for the decide loops without blocking; a full
// queue drops it and counts it.
func (e *linuxEnforcer) enqueue(r Request, queue chan<- Request) {
	select {
	case queue <- r:
	default:
		_ = r.File.Close()
		e.dropped.Add(1)
	}
}
