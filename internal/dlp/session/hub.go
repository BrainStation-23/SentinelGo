package session

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// helloTimeout bounds how long a new connection may take to say hello.
const helloTimeout = 10 * time.Second

// Hub is the service side of the IPC: it accepts session helpers, pushes the
// current policy to each, and passes their events to the sink with the user
// and session taken from the peer's OS credentials.
type Hub struct {
	addr string
	sink channel.EventSink

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	l       ipc.Listener
	policy  json.RawMessage // current bundle; nil before the first Apply
	helpers map[*helper]struct{}
	wg      sync.WaitGroup
}

// listenRetry is the wait between attempts to create the endpoint. Creating
// it can fail for a while after a restart: on Windows the old pipe lives on
// until every helper has closed its end.
var listenRetry = func(attempt int) time.Duration {
	return min(time.Second<<min(attempt, 5), 30*time.Second)
}

type helper struct {
	conn  ipc.Conn
	id    ipc.Identity
	state string
	out   chan ipc.Message // drained by the helper's writer goroutine
	done  chan struct{}    // closed when the connection is finished
}

// helperOutbox is how many messages may wait for a helper. A helper that
// stops reading fills it and is dropped, so it can never stall the service.
const helperOutbox = 4

// stopGrace is how long Stop waits for helpers to read the stop message.
var stopGrace = 2 * time.Second

// NewHub returns a hub listening on addr once started.
func NewHub(addr string, sink channel.EventSink) *Hub {
	return &Hub{addr: addr, sink: sink, helpers: map[*helper]struct{}{}}
}

// Apply starts the hub if needed and pushes p to every connected helper (and
// to each one that connects later).
func (h *Hub) Apply(_ context.Context, p *policy.Compiled) {
	raw, err := json.Marshal(p.Bundle)
	if err != nil {
		log.Printf("DLP: encode policy for helpers: %v", err)
		return
	}
	h.mu.Lock()
	h.policy = raw
	if !h.running {
		h.running = true
		h.stopCh = make(chan struct{})
		h.wg.Add(1)
		go h.serveLoop(h.stopCh)
	}
	helpers := h.snapshotLocked()
	h.mu.Unlock()

	for _, hp := range helpers {
		h.send(hp, ipc.Message{Type: ipc.TypePolicy, Policy: raw})
	}
}

// Stop tells every helper to exit, closes the endpoint and waits for the
// connection goroutines.
func (h *Hub) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	close(h.stopCh)
	l := h.l
	h.l = nil
	h.policy = nil
	helpers := h.snapshotLocked()
	h.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	for _, hp := range helpers {
		h.send(hp, ipc.Message{Type: ipc.TypeStop}) // the writer closes the conn after it
	}
	// Helpers that don't take the stop in time are cut off.
	t := time.AfterFunc(stopGrace, func() {
		for _, hp := range helpers {
			_ = hp.conn.Close()
		}
	})
	h.wg.Wait()
	t.Stop()
}

// Sessions lists the connected helpers.
func (h *Hub) Sessions() []Info {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Info, 0, len(h.helpers))
	for hp := range h.helpers {
		out = append(out, Info{User: hp.id.User, State: hp.state})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

func (h *Hub) snapshotLocked() []*helper {
	out := make([]*helper, 0, len(h.helpers))
	for hp := range h.helpers {
		out = append(out, hp)
	}
	return out
}

// serveLoop creates the endpoint, retrying until it succeeds or Stop, then
// accepts helpers until Stop closes it.
func (h *Hub) serveLoop(stop chan struct{}) {
	defer h.wg.Done()
	for attempt := 0; ; attempt++ {
		l, err := ipc.Listen(h.addr)
		if err == nil {
			h.mu.Lock()
			select {
			case <-stop: // stopped while we were creating it
				h.mu.Unlock()
				_ = l.Close()
				return
			default:
			}
			h.l = l
			h.mu.Unlock()
			h.acceptLoop(l)
			return
		}
		if attempt == 0 {
			log.Printf("DLP: session helper endpoint unavailable, retrying: %v", err)
		}
		select {
		case <-stop:
			return
		case <-time.After(listenRetry(attempt)):
		}
	}
}

func (h *Hub) acceptLoop(l ipc.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if !errors.Is(err, ipc.ErrClosed) {
				log.Printf("DLP: session helper endpoint stopped: %v", err)
			}
			return
		}
		h.wg.Add(1)
		go h.serve(c)
	}
}

// serve runs one helper connection: identify the peer, read its hello, send
// the policy, then read events and status until it disconnects.
func (h *Hub) serve(c ipc.Conn) {
	defer h.wg.Done()
	defer func() { _ = c.Close() }()

	id, err := ipc.PeerIdentity(c)
	if err != nil {
		log.Printf("DLP: rejecting helper connection: %v", err)
		return
	}
	hello, err := readHello(c)
	if err != nil {
		log.Printf("DLP: helper for %s (pid %d) did not say hello: %v", id.User, id.PID, err)
		return
	}
	hp := &helper{conn: c, id: id, state: "running", out: make(chan ipc.Message, helperOutbox), done: make(chan struct{})}
	h.wg.Add(1)
	go h.writeLoop(hp)
	h.mu.Lock()
	h.helpers[hp] = struct{}{}
	raw := h.policy
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.helpers, hp)
		h.mu.Unlock()
		close(hp.done)
	}()
	log.Printf("DLP: session helper connected for %s (session %s, pid %d, clipboard %s)",
		id.User, id.SessionID, id.PID, hello.Capabilities["clipboard"])

	if raw != nil {
		h.send(hp, ipc.Message{Type: ipc.TypePolicy, Policy: raw})
	}
	h.readLoop(hp)
}

// readHello waits (bounded) for the helper's first frame.
func readHello(c ipc.Conn) (*ipc.Hello, error) {
	type result struct {
		m   ipc.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := ipc.Read(c, ipc.MaxHelperFrame)
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if r.m.Type != ipc.TypeHello || r.m.Hello == nil {
			return nil, errors.New("first frame is " + r.m.Type)
		}
		return r.m.Hello, nil
	case <-time.After(helloTimeout):
		_ = c.Close()
		return nil, errors.New("timed out")
	}
}

func (h *Hub) readLoop(hp *helper) {
	for {
		m, err := ipc.Read(hp.conn, ipc.MaxHelperFrame)
		if err != nil {
			return // disconnect, oversized or malformed frame: drop the connection
		}
		switch m.Type {
		case ipc.TypeEvent:
			if m.Event == nil {
				continue
			}
			ev := *m.Event
			// Never trust the helper for who it is.
			ev.User = hp.id.User
			ev.SessionID = hp.id.SessionID
			h.sink.Emit(ev)
		case ipc.TypeStatus:
			if m.Status != nil {
				h.mu.Lock()
				hp.state = m.Status.State
				h.mu.Unlock()
			}
		}
	}
}

// send queues m for hp without blocking. A helper whose outbox is full isn't
// reading; it is disconnected (it reconnects and gets the current policy).
func (h *Hub) send(hp *helper, m ipc.Message) {
	select {
	case hp.out <- m:
	case <-hp.done:
	default:
		log.Printf("DLP: helper for %s isn't reading; disconnecting it", hp.id.User)
		_ = hp.conn.Close()
	}
}

// writeLoop writes queued messages to hp until its connection is done. After
// a stop message it closes the connection.
func (h *Hub) writeLoop(hp *helper) {
	defer h.wg.Done()
	for {
		select {
		case <-hp.done:
			return
		case m := <-hp.out:
			if err := ipc.Write(hp.conn, m); err != nil || m.Type == ipc.TypeStop {
				_ = hp.conn.Close() // the read loop then drops the helper
				return
			}
		}
	}
}
