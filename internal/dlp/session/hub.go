package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/sanitize"
)

// helloTimeout bounds how long a new connection may take to say hello.
const helloTimeout = 10 * time.Second

// Hub is the service side of the IPC: it accepts session helpers, pushes the
// current policy to each, and passes their events to the sink with the user
// and session taken from the peer's OS credentials.
type Hub struct {
	addr string
	sink channel.EventSink
	// files takes the files helpers hand over (TypeUserFile); nil drops
	// them. Set with SetFileReceiver.
	files FileReceiver

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	l       ipc.Listener
	policy  json.RawMessage // current bundle; nil without a DLP policy
	helpers map[*helper]struct{}
	conns   map[ipc.Conn]string // every accepted connection -> peer uid ("" before identified)
	lastErr map[string]string   // session id -> why its last connection failed

	// requireSameExe: only peers running this binary may connect (a test
	// process talks to itself, so the check holds in tests too).
	requireSameExe bool
	wg             sync.WaitGroup
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
	caps  map[string]string // from hello / status
	out   chan ipc.Message  // drained by the helper's writer goroutine
	done  chan struct{}     // closed when the connection is finished

	pending map[string]chan string             // notify id -> its result (guarded by Hub.mu)
	asks    map[string]chan ipc.OverrideAnswer // ask id -> the user's answer (guarded by Hub.mu)
	proxies map[string]chan ipc.SetProxyResult // set_proxy id -> its result (guarded by Hub.mu)
	// redirect is the session's upload redirect from its last SetProxy
	// answer (CapUploadRedirect); "" before any.
	redirect string
}

// helperOutbox is how many messages may wait for a helper. A helper that
// stops reading fills it and is dropped, so it can never stall the service.
const helperOutbox = 4

// stopGrace is how long Stop waits for helpers to read the stop message.
var stopGrace = 2 * time.Second

// Connection limits: a local user can't tie up the service by opening
// connections.
const (
	maxConns        = 64
	maxConnsPerUser = 4
)

// FileReceiver takes a file a helper handed over: from is the helper, by its
// OS identity. It runs on the helper's read loop, so it must only take its
// own copy of the handle and queue the work; the hub acks the file when it
// returns, and the helper then closes its handle.
type FileReceiver func(from ipc.Identity, f ipc.UserFile)

// SetFileReceiver sets what takes the files helpers hand over (#330).
func (h *Hub) SetFileReceiver(fn FileReceiver) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files = fn
}

// NewHub returns a hub listening on addr once started.
func NewHub(addr string, sink channel.EventSink) *Hub {
	return &Hub{addr: addr, sink: sink, helpers: map[*helper]struct{}{}, conns: map[ipc.Conn]string{}, lastErr: map[string]string{}, requireSameExe: true}
}

// Apply starts the hub if needed and pushes p to every connected helper (and
// to each one that connects later). A nil p means no DLP policy: helpers stay
// connected (for notifications) with their channels stopped.
func (h *Hub) Apply(_ context.Context, p *policy.Compiled) {
	m := ipc.Message{Type: ipc.TypeClear}
	if p != nil {
		raw, err := json.Marshal(p.Bundle)
		if err != nil {
			log.Printf("DLP: encode policy for helpers: %v", err)
			return
		}
		m = ipc.Message{Type: ipc.TypePolicy, Policy: raw}
	}
	h.mu.Lock()
	h.policy = m.Policy
	if !h.running {
		h.running = true
		h.stopCh = make(chan struct{})
		h.wg.Add(1)
		go h.serveLoop(h.stopCh)
	}
	helpers := h.snapshotLocked()
	h.mu.Unlock()

	for _, hp := range helpers {
		h.send(hp, m)
	}
}

// NotifyResult is one session's answer to Notify.
type NotifyResult struct {
	User      string
	SessionID string
	Err       string // "" when the notification was shown
	// Readiness is the session's notification readiness when it answered
	// (#323): "dnd" means shown into the notification center; "" when the
	// helper doesn't report it.
	Readiness string
}

// Notify asks every connected helper to show n and waits for each answer
// until ctx ends. The text is never logged.
func (h *Hub) Notify(ctx context.Context, n ipc.Notify) []NotifyResult {
	if n.ID == "" {
		n.ID = newNotifyID()
	}
	type wait struct {
		hp *helper
		ch chan string
	}
	h.mu.Lock()
	waits := make([]wait, 0, len(h.helpers))
	for hp := range h.helpers {
		ch := make(chan string, 1)
		if hp.pending == nil {
			hp.pending = map[string]chan string{}
		}
		hp.pending[n.ID] = ch
		waits = append(waits, wait{hp, ch})
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		for _, w := range waits {
			delete(w.hp.pending, n.ID)
		}
		h.mu.Unlock()
	}()

	for _, w := range waits {
		h.send(w.hp, ipc.Message{Type: ipc.TypeNotify, Notify: &n})
	}
	out := make([]NotifyResult, 0, len(waits))
	for _, w := range waits {
		r := NotifyResult{User: w.hp.id.User, SessionID: w.hp.id.SessionID}
		select {
		case r.Err = <-w.ch:
		case <-w.hp.done:
			r.Err = "the session helper disconnected"
		case <-ctx.Done():
			r.Err = "no answer from the session helper (it may run an older agent)"
		}
		h.mu.Lock()
		r.Readiness = w.hp.caps[CapNotifications]
		h.mu.Unlock()
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// ProxyResult is one session's answer to SetProxy: Reason is "" when the
// helper applied it, else why not (ipc.SetProxyResult's reasons, or
// no_answer).
type ProxyResult struct {
	User      string
	SessionID string
	Reason    string
	Err       string
}

// Upload redirect states a session reports under CapUploadRedirect.
const (
	redirectActive   = "active"
	redirectInactive = "inactive"
)

// SetProxy asks every connected helper to point its user's desktop proxy at
// pacURL ("" puts the user's own setting back, #426) and waits for each
// answer until ctx ends. Each session's outcome shows in Sessions under
// CapUploadRedirect.
func (h *Hub) SetProxy(ctx context.Context, pacURL string) []ProxyResult {
	req := ipc.SetProxy{ID: newNotifyID(), PACURL: pacURL}
	type wait struct {
		hp *helper
		ch chan ipc.SetProxyResult
	}
	h.mu.Lock()
	waits := make([]wait, 0, len(h.helpers))
	for hp := range h.helpers {
		ch := make(chan ipc.SetProxyResult, 1)
		if hp.proxies == nil {
			hp.proxies = map[string]chan ipc.SetProxyResult{}
		}
		hp.proxies[req.ID] = ch
		waits = append(waits, wait{hp, ch})
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		for _, w := range waits {
			delete(w.hp.proxies, req.ID)
		}
		h.mu.Unlock()
	}()

	for _, w := range waits {
		h.send(w.hp, ipc.Message{Type: ipc.TypeSetProxy, SetProxy: &req})
	}
	out := make([]ProxyResult, 0, len(waits))
	for _, w := range waits {
		r := ProxyResult{User: w.hp.id.User, SessionID: w.hp.id.SessionID}
		select {
		case res := <-w.ch:
			r.Reason, r.Err = boundError(res.Reason), boundError(res.Error)
		case <-w.hp.done:
			r.Reason, r.Err = "no_answer", "the session helper disconnected"
		case <-ctx.Done():
			r.Reason, r.Err = "no_answer", "no answer from the session helper (it may run an older agent)"
		}
		state := redirectActive
		switch {
		case r.Reason != "":
			state = "unsupported:" + r.Reason
		case pacURL == "":
			state = redirectInactive
		}
		h.mu.Lock()
		w.hp.redirect = state
		h.mu.Unlock()
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// ErrNoHelper is OpenProfile's error when the session has no connected helper.
var ErrNoHelper = errors.New("no session helper is connected for that session")

// OpenProfile asks the helper of session sessionID to present p to its user
// and waits for the answer until ctx ends. The profile bytes are never logged.
func (h *Hub) OpenProfile(ctx context.Context, sessionID string, p ipc.OpenProfile) error {
	if p.ID == "" {
		p.ID = newNotifyID()
	}
	return h.askSession(ctx, sessionID, p.ID, ipc.Message{Type: ipc.TypeOpenProfile, OpenProfile: &p})
}

// OpenURL asks the helper of session sessionID to open u for its user (an
// MDM enrollment link, #356) and waits for the answer until ctx ends.
func (h *Hub) OpenURL(ctx context.Context, sessionID string, u ipc.OpenURL) error {
	if u.ID == "" {
		u.ID = newNotifyID()
	}
	return h.askSession(ctx, sessionID, u.ID, ipc.Message{Type: ipc.TypeOpenURL, OpenURL: &u})
}

// NotifySession shows n to the user of one session (a DLP block or warning
// for the user whose process caused it) and waits for the answer until ctx
// ends. The text is never logged.
func (h *Hub) NotifySession(ctx context.Context, sessionID string, n ipc.Notify) error {
	if n.ID == "" {
		n.ID = newNotifyID()
	}
	return h.askSession(ctx, sessionID, n.ID, ipc.Message{Type: ipc.TypeNotify, Notify: &n})
}

// AskOverride asks the user of one session what to do about a blocked file
// and waits for their answer until ctx ends (a dialog waits for the user).
func (h *Hub) AskOverride(ctx context.Context, sessionID string, a ipc.AskOverride) (ipc.OverrideAnswer, error) {
	if a.ID == "" {
		a.ID = newNotifyID()
	}
	ch := make(chan ipc.OverrideAnswer, 1)
	h.mu.Lock()
	var target *helper
	for hp := range h.helpers {
		if hp.id.SessionID == sessionID {
			target = hp
			break
		}
	}
	if target != nil {
		if target.asks == nil {
			target.asks = map[string]chan ipc.OverrideAnswer{}
		}
		target.asks[a.ID] = ch
	}
	h.mu.Unlock()
	if target == nil {
		return ipc.OverrideAnswer{}, ErrNoHelper
	}
	defer func() {
		h.mu.Lock()
		delete(target.asks, a.ID)
		h.mu.Unlock()
	}()
	h.send(target, ipc.Message{Type: ipc.TypeAskOverride, AskOverride: &a})
	select {
	case ans := <-ch:
		if ans.Error != "" {
			return ans, errors.New(ans.Error)
		}
		return ans, nil
	case <-target.done:
		return ipc.OverrideAnswer{}, errors.New("the session helper disconnected")
	case <-ctx.Done():
		return ipc.OverrideAnswer{}, errors.New("no answer from the session helper")
	}
}

// SessionReadiness reports the notification readiness of the helper of one
// session; ok is false when no helper is connected for it.
func (h *Hub) SessionReadiness(sessionID string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for hp := range h.helpers {
		if hp.id.SessionID == sessionID {
			return hp.caps[CapNotifications], true
		}
	}
	return "", false
}

// askSession sends m to the helper of one session and waits for the result
// with the given id.
func (h *Hub) askSession(ctx context.Context, sessionID, id string, m ipc.Message) error {
	ch := make(chan string, 1)
	h.mu.Lock()
	var target *helper
	for hp := range h.helpers {
		if hp.id.SessionID == sessionID {
			target = hp
			break
		}
	}
	if target != nil {
		if target.pending == nil {
			target.pending = map[string]chan string{}
		}
		target.pending[id] = ch
	}
	h.mu.Unlock()
	if target == nil {
		return ErrNoHelper
	}
	defer func() {
		h.mu.Lock()
		delete(target.pending, id)
		h.mu.Unlock()
	}()

	h.send(target, m)
	select {
	case e := <-ch:
		if e != "" {
			return errors.New(e)
		}
		return nil
	case <-target.done:
		return errors.New("the session helper disconnected")
	case <-ctx.Done():
		return errors.New("no answer from the session helper (it may run an older agent)")
	}
}

func newNotifyID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
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
	// Connections that haven't said hello yet, and helpers that don't take
	// the stop in time, are cut off.
	h.mu.Lock()
	conns := make([]ipc.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	t := time.AfterFunc(stopGrace, func() {
		for _, c := range conns {
			_ = c.Close()
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
		caps := hp.caps
		if hp.redirect != "" {
			caps = make(map[string]string, len(hp.caps)+1)
			for k, v := range hp.caps {
				caps[k] = v
			}
			caps[CapUploadRedirect] = hp.redirect
		}
		out = append(out, Info{User: hp.id.User, State: hp.state, SessionID: hp.id.SessionID, Capabilities: caps})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// maxLastError bounds a session's last error in the status report.
const maxLastError = 200

// setLastError records why a connection from session failed ("" clears it).
func (h *Hub) setLastError(session, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if reason == "" {
		delete(h.lastErr, session)
		return
	}
	h.lastErr[session] = boundError(reason)
}

// boundError makes a helper-reported error (a user-controlled process) safe
// for the log and the task result.
func boundError(reason string) string {
	reason = sanitize.ForLog(reason)
	if len(reason) > maxLastError {
		reason = strings.ToValidUTF8(reason[:maxLastError], "")
	}
	return reason
}

// lastError returns why session's last connection failed, if it did.
func (h *Hub) lastError(session string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastErr[session]
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
		h.mu.Lock()
		if !h.running || len(h.conns) >= maxConns {
			h.mu.Unlock()
			_ = c.Close()
			continue
		}
		h.conns[c] = ""
		h.mu.Unlock()
		h.wg.Add(1)
		go h.serve(c)
	}
}

// admit records the peer's uid for c and reports whether it may stay: a
// running hub, this binary (when required), and few enough connections from
// the same user.
func (h *Hub) admit(c ipc.Conn, id ipc.Identity) error {
	if h.requireSameExe && !ipc.SameExecutable(id) {
		return errors.New("not the agent's own executable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return errors.New("shutting down")
	}
	n := 0
	for _, uid := range h.conns {
		if uid == id.UID {
			n++
		}
	}
	if n >= maxConnsPerUser {
		return errors.New("too many connections from this user")
	}
	h.conns[c] = id.UID
	return nil
}

// serve runs one helper connection: identify the peer, read its hello, send
// the policy, then read events and status until it disconnects.
func (h *Hub) serve(c ipc.Conn) {
	defer h.wg.Done()
	defer func() {
		_ = c.Close()
		h.mu.Lock()
		delete(h.conns, c)
		h.mu.Unlock()
	}()

	id, err := ipc.PeerIdentity(c)
	if err != nil {
		log.Printf("DLP: rejecting helper connection: %v", err)
		return
	}
	if err := h.admit(c, id); err != nil {
		log.Printf("DLP: rejecting helper connection from %s (pid %d, %s): %v",
			sanitize.ForLog(id.User), id.PID, sanitize.ForLog(id.Exe), err)
		h.setLastError(id.SessionID, "helper rejected: "+err.Error())
		return
	}
	hello, err := readHello(c)
	if err != nil {
		log.Printf("DLP: helper for %s (pid %d) did not say hello: %v", sanitize.ForLog(id.User), id.PID, err)
		reason := "helper did not say hello: " + err.Error()
		if errors.Is(err, io.EOF) {
			// What a helper that doesn't trust the endpoint does.
			reason = "helper disconnected before hello (it may not trust the service endpoint)"
		}
		h.setLastError(id.SessionID, reason)
		return
	}
	h.setLastError(id.SessionID, "")
	hp := &helper{conn: c, id: id, state: "running", caps: sanitizeCaps(hello.Capabilities), out: make(chan ipc.Message, helperOutbox), done: make(chan struct{})}
	h.mu.Lock()
	if !h.running { // Stop ran while this helper was saying hello
		h.mu.Unlock()
		return
	}
	h.helpers[hp] = struct{}{}
	raw := h.policy
	h.mu.Unlock()
	h.wg.Add(1)
	go h.writeLoop(hp)
	defer func() {
		h.mu.Lock()
		delete(h.helpers, hp)
		h.mu.Unlock()
		close(hp.done)
	}()
	log.Printf("DLP: session helper connected for %s (session %s, pid %d, clipboard %s)",
		sanitize.ForLog(id.User), id.SessionID, id.PID, sanitize.ForLog(hello.Capabilities["clipboard"]))

	if raw != nil {
		h.send(hp, ipc.Message{Type: ipc.TypePolicy, Policy: raw})
	}
	h.readLoop(hp)
}

// sanitizeCaps keeps a few short capability strings from a helper, which is
// a user-controlled process: they go into logs and the status report.
func sanitizeCaps(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if len(out) == 8 || len(k) > 32 || len(v) > 64 {
			continue
		}
		out[sanitize.ForLog(k)] = sanitize.ForLog(v)
	}
	return out
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
		h.handle(hp, m)
	}
}

// handle acts on one message from a helper.
func (h *Hub) handle(hp *helper, m ipc.Message) {
	switch {
	case m.Type == ipc.TypeEvent && m.Event != nil:
		ev := *m.Event
		// Never trust the helper for who it is.
		ev.User = hp.id.User
		ev.SessionID = hp.id.SessionID
		h.sink.Emit(ev)
	case m.Type == ipc.TypeUserFile && m.UserFile != nil:
		h.takeFile(hp, *m.UserFile)
	case m.Type == ipc.TypeNotifyResult && m.NotifyResult != nil:
		h.answer(hp, m.NotifyResult.ID, m.NotifyResult.Error)
	case m.Type == ipc.TypeOpenProfileResult && m.OpenProfileResult != nil:
		h.answer(hp, m.OpenProfileResult.ID, m.OpenProfileResult.Error)
	case m.Type == ipc.TypeOpenURLResult && m.OpenURLResult != nil:
		h.answer(hp, m.OpenURLResult.ID, m.OpenURLResult.Error)
	case m.Type == ipc.TypeSetProxyResult && m.SetProxyResult != nil:
		h.proxyAnswer(hp, *m.SetProxyResult)
	case m.Type == ipc.TypeOverrideAnswer && m.OverrideAnswer != nil:
		h.overrideAnswer(hp, *m.OverrideAnswer)
	case m.Type == ipc.TypeStatus && m.Status != nil:
		h.mu.Lock()
		hp.state = m.Status.State
		if m.Status.Capabilities != nil {
			hp.caps = sanitizeCaps(m.Status.Capabilities)
		}
		h.mu.Unlock()
	}
}

// takeFile gives a handed-over file to the receiver, then acks it so the
// helper closes its handle.
func (h *Hub) takeFile(hp *helper, f ipc.UserFile) {
	h.mu.Lock()
	fn := h.files
	h.mu.Unlock()
	if fn != nil {
		fn(hp.id, f)
	}
	h.send(hp, ipc.Message{Type: ipc.TypeUserFileAck, UserFileAck: &ipc.UserFileAck{ID: f.ID}})
}

// overrideAnswer delivers the user's answer to the AskOverride waiting on it.
func (h *Hub) overrideAnswer(hp *helper, a ipc.OverrideAnswer) {
	h.mu.Lock()
	ch := hp.asks[a.ID]
	h.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- a:
	default:
	}
}

// proxyAnswer delivers a helper's SetProxy result to the call waiting on it.
func (h *Hub) proxyAnswer(hp *helper, r ipc.SetProxyResult) {
	h.mu.Lock()
	ch := hp.proxies[r.ID]
	delete(hp.proxies, r.ID)
	h.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// answer delivers a helper's result to the request waiting on id, if any.
func (h *Hub) answer(hp *helper, id, errText string) {
	h.mu.Lock()
	ch := hp.pending[id]
	delete(hp.pending, id)
	h.mu.Unlock()
	if ch != nil {
		ch <- boundError(errText)
	}
}

// send queues m for hp without blocking. A helper whose outbox is full isn't
// reading; it is disconnected (it reconnects and gets the current policy).
func (h *Hub) send(hp *helper, m ipc.Message) {
	select {
	case hp.out <- m:
	case <-hp.done:
	default:
		log.Printf("DLP: helper for %s isn't reading; disconnecting it", sanitize.ForLog(hp.id.User))
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
