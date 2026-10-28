package session

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// maxBufferedEvents bounds the events a helper holds while the service is
// unreachable; the oldest are dropped beyond it.
const maxBufferedEvents = 100

// HelperOptions configures a session helper.
type HelperOptions struct {
	Addr     string            // the service endpoint (ipc.DefaultAddress)
	Version  string            // agent version, sent in hello
	Channels []channel.Channel // what this helper watches

	// Backoff is the wait before reconnect attempt n (n >= 1). Defaults to
	// 1 s doubling to 30 s.
	Backoff func(n int) time.Duration
}

func defaultBackoff(n int) time.Duration {
	d := time.Second << min(n-1, 5)
	return min(d, 30*time.Second)
}

// RunHelper is `sentinelgo dlp-session`: it connects to the service, enforces
// the policy it receives with the configured channels, and sends events back.
// When the service is unreachable it keeps enforcing the last policy and
// reconnects with backoff. It returns nil when the service says stop, when
// the policy turns DLP off, or when ctx ends.
func RunHelper(ctx context.Context, o HelperOptions) error {
	if o.Backoff == nil {
		o.Backoff = defaultBackoff
	}
	r := &helperRuntime{o: o}
	defer r.stopChannels()
	for attempt := 0; ; {
		if ctx.Err() != nil {
			return nil
		}
		stop, err := r.connectOnce(ctx)
		if stop {
			return nil
		}
		if err == nil {
			attempt = 0 // connected and then lost: retry soon
		}
		attempt++
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(o.Backoff(attempt)):
		}
	}
}

type helperRuntime struct {
	o HelperOptions

	mu      sync.Mutex
	conn    ipc.Conn // nil while disconnected
	buffer  []events.Event
	version string // applied bundle version

	chCancel context.CancelFunc
	chWG     sync.WaitGroup
}

// connectOnce runs one connection. stop is true when the helper should exit.
func (r *helperRuntime) connectOnce(ctx context.Context) (stop bool, err error) {
	c, err := ipc.Dial(ctx, r.o.Addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()
	if id, err := ipc.ServerIdentity(c); err != nil || !ipc.TrustedServer(id) {
		log.Printf("DLP helper: refusing endpoint %s served by %s (%v)", r.o.Addr, id.User, err)
		return false, errors.New("untrusted endpoint")
	}

	// Unblock the read below when ctx ends.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()

	if err := ipc.Write(c, ipc.Message{Type: ipc.TypeHello, Hello: &ipc.Hello{
		PID: os.Getpid(), Version: r.o.Version, Capabilities: r.capabilities(),
	}}); err != nil {
		return false, err
	}
	r.attach(c)
	defer r.detach()

	for {
		m, err := ipc.Read(c, ipc.MaxServiceFrame)
		if err != nil {
			return false, nil // lost the service: keep enforcing, reconnect
		}
		switch m.Type {
		case ipc.TypeStop:
			log.Printf("DLP helper: service asked to stop")
			return true, nil
		case ipc.TypePolicy:
			if r.apply(ctx, m.Policy) {
				log.Printf("DLP helper: DLP is off; exiting")
				return true, nil
			}
		}
	}
}

func (r *helperRuntime) capabilities() map[string]string {
	caps := map[string]string{}
	for _, ch := range r.o.Channels {
		caps[ch.Name()] = ch.Supported().String()
	}
	return caps
}

// apply enforces a new bundle. It returns true when the bundle turns DLP off.
func (r *helperRuntime) apply(ctx context.Context, raw json.RawMessage) (off bool) {
	b, err := policy.Decode(raw)
	if err != nil {
		log.Printf("DLP helper: ignoring policy: %v", err)
		return false
	}
	if !b.Enabled {
		return true
	}
	r.mu.Lock()
	same := b.Version == r.version
	r.mu.Unlock()
	if same {
		return false
	}
	c := policy.Compile(b)
	r.stopChannels()

	chCtx, cancel := context.WithCancel(ctx)
	r.chCancel = cancel
	running := 0
	for _, ch := range r.o.Channels {
		if !c.ChannelEnabled(ch.Name()) || !ch.Supported().Supported {
			continue
		}
		running++
		r.chWG.Add(1)
		go func(ch channel.Channel) {
			defer r.chWG.Done()
			if err := ch.Run(chCtx, c, r); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("DLP helper: %s channel stopped: %v", ch.Name(), err)
			}
		}(ch)
	}
	r.mu.Lock()
	r.version = b.Version
	r.mu.Unlock()

	state := "running"
	if running == 0 {
		state = "idle"
	}
	r.send(ipc.Message{Type: ipc.TypeStatus, Status: &ipc.Status{State: state, Capabilities: r.capabilities()}})
	return false
}

func (r *helperRuntime) stopChannels() {
	if r.chCancel != nil {
		r.chCancel()
		r.chWG.Wait()
		r.chCancel = nil
	}
}

// Emit implements channel.EventSink: send now, or buffer while disconnected.
func (r *helperRuntime) Emit(ev events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil && ipc.Write(r.conn, ipc.Message{Type: ipc.TypeEvent, Event: &ev}) == nil {
		return
	}
	r.buffer = append(r.buffer, ev)
	if len(r.buffer) > maxBufferedEvents {
		r.buffer = r.buffer[len(r.buffer)-maxBufferedEvents:]
	}
}

func (r *helperRuntime) send(m ipc.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_ = ipc.Write(r.conn, m)
	}
}

// attach makes c the live connection and flushes buffered events to it.
func (r *helperRuntime) attach(c ipc.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conn = c
	for len(r.buffer) > 0 {
		if ipc.Write(c, ipc.Message{Type: ipc.TypeEvent, Event: &r.buffer[0]}) != nil {
			return
		}
		r.buffer = r.buffer[1:]
	}
}

func (r *helperRuntime) detach() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conn = nil
}
