package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/notify"
	"sentinelgo/internal/dlp/policy"
)

// maxUntrusted is how many endpoints in a row a helper refuses before it
// exits, so the launcher reports it restarting instead of starting forever.
const maxUntrusted = 5

// errUntrusted: the endpoint isn't served by the service account.
var errUntrusted = errors.New("untrusted endpoint")

// trustServer decides whether the helper takes policy from an endpoint's
// owner; tests replace it.
var trustServer = ipc.TrustedServer

// refusedLinger bounds how long a helper that refused an endpoint waits for
// it to hang up (a var for tests), and refusedDrain how much it reads (and
// discards) meanwhile.
var refusedLinger = 2 * time.Second

const refusedDrain = 64 << 10

// maxBufferedEvents bounds the events a helper holds while the service is
// unreachable; the oldest are dropped beyond it.
const maxBufferedEvents = 100

// channelRecheck is how often a channel that can't run is checked again (a
// tool installed, an X server started), and the longest wait before a failed
// channel is restarted. A var for tests.
var channelRecheck = time.Minute

// HelperOptions configures a session helper.
type HelperOptions struct {
	Addr     string            // the service endpoint (ipc.DefaultAddress)
	Version  string            // agent version, sent in hello
	Channels []channel.Channel // what this helper watches
	// Notify shows an admin's desktop notification and waits for it; nil
	// means this helper can't show one.
	Notify func(title, message, level string) error
	// OpenProfile presents a configuration profile to the user (#350); nil
	// means this platform can't.
	OpenProfile func(name string, data []byte) error
	// OpenURL opens an MDM enrollment link for the user (#356); nil means
	// this platform can't.
	OpenURL func(url string) error
	// Readiness reads whether a notification can reach this user (#323,
	// notify.Readiness); nil means it isn't reported.
	Readiness func() (state, detail string)
	// AskOverride shows the block_override dialog (#336, prompt.Show); nil
	// means this helper can't, and answers cancel.
	AskOverride func(ctx context.Context, a ipc.AskOverride) (choice, reason string, err error)

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
// reconnects with backoff. Without a DLP policy it stays connected with its
// channels stopped, to show the service's notifications. It returns nil when
// the service says stop or when ctx ends, and an error after maxUntrusted
// untrusted endpoints in a row.
func RunHelper(ctx context.Context, o HelperOptions) error {
	if o.Backoff == nil {
		o.Backoff = defaultBackoff
	}
	r := &helperRuntime{o: o}
	defer r.stopChannels()
	if o.Readiness != nil {
		r.refreshReadiness()
		// The watcher ends with the helper, whether ctx ends or the service
		// says stop: it must not outlive RunHelper.
		var wg sync.WaitGroup
		defer wg.Wait() // runs after cancel (defers run last first)
		wctx, cancel := context.WithCancel(ctx)
		defer cancel()
		wg.Add(1)
		go func() { defer wg.Done(); r.watchReadiness(wctx) }()
	}
	for attempt, untrusted := 0, 0; ; {
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
		if errors.Is(err, errUntrusted) {
			if untrusted++; untrusted >= maxUntrusted {
				return fmt.Errorf("%s refused %d times in a row: %w", o.Addr, untrusted, err)
			}
		} else {
			untrusted = 0
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
	version string          // applied bundle version
	running map[string]bool // channels whose Run is active
	sent    string          // the last status sent, to skip repeats
	ready   string          // notification readiness, "" when not read
	// handoffs are files handed to the service, waiting for its ack.
	handoffs map[string]*pendingHandoff

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
	if id, err := ipc.ServerIdentity(c); err != nil || !trustServer(id) {
		log.Printf("DLP helper: refusing endpoint %s served by %s (%v)", r.o.Addr, id.User, err)
		lingerRefused(c)
		return false, errUntrusted
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
		if m.Type == ipc.TypeStop {
			log.Printf("DLP helper: service asked to stop")
			return true, nil
		}
		r.dispatch(ctx, m)
	}
}

// dispatch handles one message from the service; slow ones (anything that
// waits for the user) run in their own goroutine.
func (r *helperRuntime) dispatch(ctx context.Context, m ipc.Message) {
	switch m.Type {
	case ipc.TypePolicy:
		r.apply(ctx, m.Policy)
	case ipc.TypeClear:
		r.clear()
	case ipc.TypeNotify:
		if m.Notify != nil {
			go r.notify(*m.Notify)
		}
	case ipc.TypeOpenProfile:
		if m.OpenProfile != nil {
			go r.openProfile(*m.OpenProfile)
		}
	case ipc.TypeOpenURL:
		if m.OpenURL != nil {
			go r.openURL(*m.OpenURL)
		}
	case ipc.TypeAskOverride:
		if m.AskOverride != nil {
			go r.askOverride(ctx, *m.AskOverride)
		}
	case ipc.TypeUserFileAck:
		if m.UserFileAck != nil {
			r.released(m.UserFileAck.ID)
		}
	}
}

func (r *helperRuntime) capabilities() map[string]string {
	caps := map[string]string{}
	for _, ch := range r.o.Channels {
		caps[ch.Name()] = ch.Supported().String()
	}
	r.mu.Lock()
	if r.ready != "" {
		caps[CapNotifications] = r.ready
	}
	r.mu.Unlock()
	return caps
}

// refreshReadiness reads notification readiness and reports whether it
// changed.
func (r *helperRuntime) refreshReadiness() bool {
	if r.o.Readiness == nil {
		return false
	}
	state, _ := r.o.Readiness()
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := state != r.ready
	r.ready = state
	return changed
}

// watchReadiness re-reads readiness every channelRecheck, and tells the
// service when it changed (a user turning notifications off shows up within
// a minute, with or without a DLP policy).
func (r *helperRuntime) watchReadiness(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(channelRecheck):
		}
		if r.refreshReadiness() {
			r.sendStatus(false)
		}
	}
}

// apply enforces a new bundle; one that turns DLP off stops the channels.
func (r *helperRuntime) apply(ctx context.Context, raw json.RawMessage) {
	b, err := policy.Decode(raw)
	if err != nil {
		log.Printf("DLP helper: ignoring policy: %v", err)
		return
	}
	if !b.Enabled {
		r.clear()
		return
	}
	r.mu.Lock()
	same := b.Version == r.version
	r.mu.Unlock()
	if same {
		r.sendStatus(false) // e.g. a new connection after a service restart
		return
	}
	c := policy.Compile(b)
	r.stopChannels()

	chCtx, cancel := context.WithCancel(ctx)
	r.chCancel = cancel
	for _, ch := range r.o.Channels {
		if !c.ChannelEnabled(ch.Name()) {
			continue
		}
		supported := ch.Supported().Supported
		r.setRunning(ch.Name(), supported)
		r.chWG.Add(1)
		go func(ch channel.Channel) {
			defer r.chWG.Done()
			r.supervise(chCtx, ch, c, supported)
		}(ch)
	}
	r.mu.Lock()
	r.version = b.Version
	r.mu.Unlock()
	r.sendStatus(true)
}

// supervise runs ch for the bundle until ctx ends. A channel that can't run
// here yet starts once it can, and one whose Run fails is restarted with
// backoff; both are checked at most channelRecheck apart, and the service
// hears of each change.
func (r *helperRuntime) supervise(ctx context.Context, ch channel.Channel, c *policy.Compiled, supported bool) {
	for failures := 0; ; {
		wait := channelRecheck
		if supported {
			r.setRunning(ch.Name(), true)
			r.sendStatus(false)
			started := time.Now()
			err := ch.Run(ctx, c, r)
			r.setRunning(ch.Name(), false)
			if ctx.Err() != nil {
				return
			}
			if time.Since(started) > channelRecheck {
				failures = 0 // it ran for a while: not a crash loop
			}
			if !errors.Is(err, channel.ErrUnsupported) {
				failures++
				wait = min(time.Second<<min(failures-1, 6), channelRecheck)
				log.Printf("DLP helper: %s channel stopped: %v; restarting in %v", ch.Name(), err, wait)
			}
		}
		r.sendStatus(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		supported = ch.Supported().Supported
	}
}

func (r *helperRuntime) setRunning(name string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == nil {
		r.running = map[string]bool{}
	}
	r.running[name] = on
}

// sendStatus tells the service the helper's state and capabilities: always
// when force is set, otherwise only when they changed since the last one.
func (r *helperRuntime) sendStatus(force bool) {
	caps := r.capabilities()
	r.mu.Lock()
	state := "idle"
	if r.version != "" {
		for _, on := range r.running {
			if on {
				state = "running"
			}
		}
	}
	key := fmt.Sprint(state, caps) // maps print sorted
	if !force && key == r.sent {
		r.mu.Unlock()
		return
	}
	r.sent = key
	r.mu.Unlock()
	r.send(ipc.Message{Type: ipc.TypeStatus, Status: &ipc.Status{State: state, Capabilities: caps}})
}

// clear stops the channels: no DLP policy. The helper stays connected.
func (r *helperRuntime) clear() {
	r.stopChannels()
	r.mu.Lock()
	had := r.version != ""
	r.version = ""
	r.mu.Unlock()
	if had {
		log.Printf("DLP helper: no DLP policy; channels stopped")
	}
	r.sendStatus(true)
}

// notify shows an admin's notification and answers with the result. The
// text is never logged; the error carries the tool and exit status only.
func (r *helperRuntime) notify(n ipc.Notify) {
	res := &ipc.NotifyResult{ID: n.ID}
	// Read readiness just before showing, and tell the service first, so
	// the result it records matches what the user can see.
	if r.refreshReadiness() {
		r.sendStatus(false)
	}
	r.mu.Lock()
	ready := r.ready
	r.mu.Unlock()
	if r.o.Notify == nil {
		res.Error = "this helper can't show notifications"
	} else if err := r.o.Notify(n.Title, n.Message, n.Level); err != nil {
		log.Printf("Session helper: notification %s failed: %v", n.ID, err)
		res.Error = err.Error()
	} else if !notify.Shows(ready) {
		// The tool exits 0 even when the OS hides the notification.
		res.Error = "notifications are off for this user (" + ready + ")"
	}
	r.send(ipc.Message{Type: ipc.TypeNotifyResult, NotifyResult: res})
}

// askOverrideWait bounds how long a block_override dialog stays open.
const askOverrideWait = 10 * time.Minute

// askOverride shows the block_override dialog and answers with the user's
// choice. The reason is never logged.
func (r *helperRuntime) askOverride(ctx context.Context, a ipc.AskOverride) {
	ans := &ipc.OverrideAnswer{ID: a.ID, Choice: "cancel"}
	if r.o.AskOverride == nil {
		ans.Error = "this helper can't ask"
	} else {
		ctx, cancel := context.WithTimeout(ctx, askOverrideWait)
		choice, reason, err := r.o.AskOverride(ctx, a)
		cancel()
		if err != nil {
			log.Printf("Session helper: override dialog %s failed: %v", a.ID, err)
			ans.Error = err.Error()
		} else {
			ans.Choice, ans.Reason = choice, reason
		}
	}
	r.send(ipc.Message{Type: ipc.TypeOverrideAnswer, OverrideAnswer: ans})
}

// openProfile presents a configuration profile to this helper's user, then
// tells them what to do with it. The profile's bytes are never logged.
func (r *helperRuntime) openProfile(p ipc.OpenProfile) {
	res := &ipc.OpenProfileResult{ID: p.ID}
	if r.o.OpenProfile == nil {
		res.Error = "this helper can't open configuration profiles on this platform"
	} else if err := r.o.OpenProfile(p.Name, p.Data); err != nil {
		log.Printf("Session helper: profile %s not opened: %v", p.ID, err)
		res.Error = err.Error()
	} else if r.o.Notify != nil && p.Title != "" {
		if err := r.o.Notify(p.Title, p.Message, ipc.LevelWarning); err != nil {
			log.Printf("Session helper: profile %s opened; instructions not shown: %v", p.ID, err)
		}
	}
	r.send(ipc.Message{Type: ipc.TypeOpenProfileResult, OpenProfileResult: res})
}

// enrollmentScheme is the only kind of link a helper opens: Windows' MDM
// enrollment, which starts Settings > Access work or school.
const enrollmentScheme = "ms-device-enrollment:"

// openURL opens an MDM enrollment link for this helper's user, then tells
// them what to do.
func (r *helperRuntime) openURL(u ipc.OpenURL) {
	res := &ipc.OpenProfileResult{ID: u.ID}
	switch {
	case !strings.HasPrefix(strings.ToLower(u.URL), enrollmentScheme):
		res.Error = "the helper opens MDM enrollment links only"
	case r.o.OpenURL == nil:
		res.Error = "this helper can't open enrollment links on this platform"
	default:
		if err := r.o.OpenURL(u.URL); err != nil {
			log.Printf("Session helper: enrollment link %s not opened: %v", u.ID, err)
			res.Error = err.Error()
		} else if r.o.Notify != nil && u.Title != "" {
			if err := r.o.Notify(u.Title, u.Message, ipc.LevelWarning); err != nil {
				log.Printf("Session helper: link %s opened; instructions not shown: %v", u.ID, err)
			}
		}
	}
	r.send(ipc.Message{Type: ipc.TypeOpenURLResult, OpenURLResult: res})
}

func (r *helperRuntime) stopChannels() {
	if r.chCancel != nil {
		r.chCancel()
		r.chWG.Wait()
		r.chCancel = nil
	}
	r.mu.Lock()
	r.running = nil
	r.mu.Unlock()
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
	r.sent = "" // a new connection hasn't heard any status yet
	for len(r.buffer) > 0 {
		if ipc.Write(c, ipc.Message{Type: ipc.TypeEvent, Event: &r.buffer[0]}) != nil {
			return
		}
		r.buffer = r.buffer[1:]
	}
}

func (r *helperRuntime) detach() {
	r.mu.Lock()
	r.conn = nil
	r.mu.Unlock()
	r.releaseAll()
}

// lingerRefused ends a refused connection without sending anything: it
// closes the write side, so the service reads EOF where the hello would be,
// and waits for the service to hang up. Closing outright races the service
// reading the peer's credentials, which macOS can't report once the socket
// is disconnected; the service then can't record why this helper never
// connected. An endpoint that doesn't hang up is left after refusedLinger.
func lingerRefused(c ipc.Conn) {
	hc, ok := c.(interface {
		CloseWrite() error
		SetReadDeadline(time.Time) error
	})
	if !ok || hc.CloseWrite() != nil {
		return
	}
	_ = hc.SetReadDeadline(time.Now().Add(refusedLinger))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, refusedDrain))
}
