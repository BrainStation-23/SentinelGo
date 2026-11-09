package session

// Handing files to the service (#330). A channel that finds a file only the
// user's session can see (a mapped network drive, a sync folder) opens it
// and hands the open handle over; the service duplicates it, decides, and
// acks. The helper keeps its handle until the ack, a disconnect, or
// handoffTimeout, then calls release: the service has its own copy by then
// or isn't going to take one, so closing ours is always safe.

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"sentinelgo/internal/dlp/ipc"
)

// FileHandoff is what a helper channel hands files to. The channel's
// EventSink implements it in the helper.
type FileHandoff interface {
	// HandOff sends f to the service; release is called exactly once, when
	// the helper's handle can be closed.
	HandOff(f ipc.UserFile, release func())
}

// handoffTimeout bounds how long a handed-over handle stays open without an
// ack; maxHandoffs how many may wait at once (beyond it, files are released
// without being sent). Vars for tests.
var (
	handoffTimeout = time.Minute
	maxHandoffs    = 256
)

type pendingHandoff struct {
	release func()
	timer   *time.Timer
}

// HandOff implements FileHandoff.
func (r *helperRuntime) HandOff(f ipc.UserFile, release func()) {
	if f.ID == "" {
		f.ID = newHandoffID()
	}
	r.mu.Lock()
	if r.conn == nil || len(r.handoffs) >= maxHandoffs {
		r.mu.Unlock()
		release() // no service to take it: the file isn't decided
		return
	}
	if r.handoffs == nil {
		r.handoffs = map[string]*pendingHandoff{}
	}
	p := &pendingHandoff{release: release}
	r.handoffs[f.ID] = p
	p.timer = time.AfterFunc(handoffTimeout, func() { r.released(f.ID) })
	err := ipc.Write(r.conn, ipc.Message{Type: ipc.TypeUserFile, UserFile: &f})
	r.mu.Unlock()
	if err != nil {
		r.released(f.ID)
	}
}

// released closes a handed-over handle (ack, timeout or failure); a second
// call for the same file does nothing.
func (r *helperRuntime) released(id string) {
	r.mu.Lock()
	p := r.handoffs[id]
	delete(r.handoffs, id)
	r.mu.Unlock()
	if p == nil {
		return
	}
	p.timer.Stop()
	p.release()
}

// releaseAll closes every waiting handle (disconnected: the service has
// its copies of what it took).
func (r *helperRuntime) releaseAll() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.handoffs))
	for id := range r.handoffs {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.released(id)
	}
}

func newHandoffID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
