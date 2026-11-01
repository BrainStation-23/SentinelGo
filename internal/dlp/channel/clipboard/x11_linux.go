//go:build linux

package clipboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// The native X11 backend speaks the X protocol itself (pure Go, no tools):
// on X11 sessions, and through XWayland on Wayland desktops, whose
// compositors mirror the clipboard to X11 both ways (GNOME, KDE, wlroots).
// XFixes reports every new owner of CLIPBOARD, so each copy, even of the
// same text again, is seen as it happens without polling.
const (
	x11Timeout  = 2 * time.Second  // one selection conversion, or INCR chunk
	x11RetryMax = 30 * time.Second // reconnect backoff cap
	x11Property = "SENTINELGO_CLIPBOARD"
)

var (
	errXClosed  = errors.New("X11 connection closed")
	errXTimeout = errors.New("X11 selection owner didn't answer")
	errXRefused = errors.New("X11 selection owner refused the conversion")
)

// textTargets are the text types read from a copy, most preferred first.
var textTargets = []string{"UTF8_STRING", "text/plain;charset=utf-8", "STRING", "text/plain", "TEXT"}

func init() {
	// xgb logs unrecoverable connection errors on its own; keep them in the
	// helper's log. They never carry clipboard content.
	xgb.Logger = log.New(xgbLog{}, "DLP helper: X11: ", 0)
}

// xgbLog writes to the standard logger's current output, which the helper
// points at its log file after start. The notes xgb prints on every
// connection without an Xauthority file (normal under Xvfb and xhost
// setups) are dropped, so probing doesn't fill the log.
type xgbLog struct{}

func (xgbLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("authority info")) {
		return len(p), nil
	}
	return log.Writer().Write(p)
}

// x11Probe reports whether the session's X server is reachable and has
// XFixes (a seam for tests).
var x11Probe = func() (connected, xfixes bool) {
	conn, err := xgb.NewConn()
	if err != nil {
		return false, false
	}
	defer conn.Close()
	return true, initXFixes(conn) == nil
}

func initXFixes(conn *xgb.Conn) error {
	if err := xfixes.Init(conn); err != nil {
		return err
	}
	_, err := xfixes.QueryVersion(conn, 2, 0).Reply()
	return err
}

// runX11 watches the clipboard until ctx ends, reconnecting when the X
// server goes away (XWayland can be restarted under a running session).
func runX11(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	log.Printf("DLP helper: clipboard via x11-native (DISPLAY %s)", os.Getenv("DISPLAY"))
	backoff, failing := time.Second, false
	for {
		c, err := dialX11()
		if err == nil {
			if failing {
				log.Printf("DLP helper: X11 clipboard reconnected")
			}
			backoff, failing = time.Second, false
			err = c.watch(ctx, p, sink)
			c.close()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !failing {
			log.Printf("DLP helper: X11 clipboard unavailable (%v); retrying", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, x11RetryMax)
	}
}

// x11Clipboard is one connection watching CLIPBOARD. Only the goroutine that
// calls watch uses it; a reader goroutine just forwards events.
type x11Clipboard struct {
	conn  *xgb.Conn
	root  xproto.Window
	win   xproto.Window // our unmapped window: requestor and owner
	mask  uint32        // resource id mask: ids of one client share id &^ mask
	atoms map[string]xproto.Atom

	events chan xgb.Event
	done   chan struct{}
	queue  []xgb.Event // events put aside while waiting for a conversion

	owned []byte // the placeholder while we own CLIPBOARD
}

func dialX11() (*x11Clipboard, error) {
	conn, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	c, err := newX11Clipboard(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func newX11Clipboard(conn *xgb.Conn) (*x11Clipboard, error) {
	if err := initXFixes(conn); err != nil {
		return nil, fmt.Errorf("XFixes: %w", err)
	}
	setup := xproto.Setup(conn)
	screen := setup.DefaultScreen(conn)
	win, err := xproto.NewWindowId(conn)
	if err != nil {
		return nil, err
	}
	if err := xproto.CreateWindowChecked(conn, 0, win, screen.Root, 0, 0, 1, 1, 0,
		xproto.WindowClassInputOnly, screen.RootVisual,
		xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check(); err != nil {
		return nil, fmt.Errorf("create window: %w", err)
	}
	c := &x11Clipboard{
		conn: conn, root: screen.Root, win: win, mask: setup.ResourceIdMask,
		atoms:  map[string]xproto.Atom{},
		events: make(chan xgb.Event, 64),
		done:   make(chan struct{}),
	}
	clip, err := c.atom("CLIPBOARD")
	if err != nil {
		return nil, err
	}
	if err := xfixes.SelectSelectionInputChecked(conn, win, clip, xfixes.SelectionEventMaskSetSelectionOwner).Check(); err != nil {
		return nil, fmt.Errorf("select CLIPBOARD owner events: %w", err)
	}
	go c.read()
	return c, nil
}

// read forwards events until the connection closes. X errors of requests
// sent without a reply (a conversion of a gone window) are dropped: the
// waiting side times out instead.
func (c *x11Clipboard) read() {
	defer close(c.events)
	for {
		ev, xerr := c.conn.WaitForEvent()
		if ev == nil && xerr == nil {
			return
		}
		if ev == nil {
			continue
		}
		select {
		case c.events <- ev:
		case <-c.done:
			return
		}
	}
}

func (c *x11Clipboard) close() {
	close(c.done)
	c.conn.Close()
}

func (c *x11Clipboard) atom(name string) (xproto.Atom, error) {
	if a, ok := c.atoms[name]; ok {
		return a, nil
	}
	r, err := xproto.InternAtom(c.conn, false, uint16(len(name)), name).Reply()
	if err != nil {
		return 0, err
	}
	c.atoms[name] = r.Atom
	return r.Atom, nil
}

// mustAtom is atom for names already interned by watch (it can't fail then).
func (c *x11Clipboard) mustAtom(name string) xproto.Atom {
	a, _ := c.atom(name)
	return a
}

// watch handles events until the connection fails or ctx ends.
func (c *x11Clipboard) watch(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	for _, name := range append([]string{"CLIPBOARD", "TARGETS", "INCR", x11Property, hintTarget, "_NET_ACTIVE_WINDOW", "_NET_WM_PID"}, textTargets...) {
		if _, err := c.atom(name); err != nil {
			return err
		}
	}
	for {
		ev, err := c.nextEvent(ctx)
		if err != nil {
			return err
		}
		switch e := ev.(type) {
		case xproto.SelectionRequestEvent:
			c.serve(e)
		case xproto.SelectionClearEvent:
			c.owned = nil // a newer copy took over from our placeholder
		case xfixes.SelectionNotifyEvent:
			if e.Owner == c.win || e.Owner == 0 {
				continue // our placeholder, or the clipboard emptied
			}
			if err := c.onCopy(ctx, p, sink, e); errors.Is(err, errXClosed) || ctx.Err() != nil {
				return err
			}
		}
	}
}

func (c *x11Clipboard) nextEvent(ctx context.Context) (xgb.Event, error) {
	if len(c.queue) > 0 {
		ev := c.queue[0]
		c.queue = c.queue[1:]
		return ev, nil
	}
	return c.recv(ctx, time.Time{})
}

// recv takes the next event from the server; a zero deadline waits forever.
func (c *x11Clipboard) recv(ctx context.Context, deadline time.Time) (xgb.Event, error) {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case ev, ok := <-c.events:
		if !ok {
			return nil, errXClosed
		}
		return ev, nil
	case <-timeout:
		return nil, errXTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// await waits for an event match accepts. Meanwhile it answers requests for
// our placeholder (an app waiting on us would otherwise stall) and puts
// every other event aside for watch.
func (c *x11Clipboard) await(ctx context.Context, match func(xgb.Event) bool) (xgb.Event, error) {
	deadline := time.Now().Add(x11Timeout)
	for {
		ev, err := c.recv(ctx, deadline)
		if err != nil {
			return nil, err
		}
		if r, ok := ev.(xproto.SelectionRequestEvent); ok {
			c.serve(r)
			continue
		}
		if match(ev) {
			return ev, nil
		}
		c.queue = append(c.queue, ev)
	}
}

// onCopy scans a new copy and acts on it.
func (c *x11Clipboard) onCopy(ctx context.Context, p *policy.Compiled, sink channel.EventSink, e xfixes.SelectionNotifyEvent) error {
	targets, err := c.convert(ctx, "TARGETS", e.Timestamp)
	if errors.Is(err, errXClosed) || ctx.Err() != nil {
		return err
	}
	offered := atomSet(targets) // empty when the owner can't list them: try UTF8_STRING anyway
	if p.Modules.Clipboard.IgnoreConcealed && offered[c.mustAtom(hintTarget)] {
		return nil
	}
	target := "UTF8_STRING"
	if len(offered) > 0 {
		target = ""
		for _, t := range textTargets {
			if offered[c.mustAtom(t)] {
				target = t
				break
			}
		}
		if target == "" {
			return nil // not text (an image, files)
		}
	}
	text, err := c.convert(ctx, target, e.Timestamp)
	if err != nil || len(text) == 0 {
		return err
	}
	enforce(p, sink, text, c.sourceApp(e.Owner), func(msg string) error {
		return c.replace(e, msg)
	})
	return nil
}

// atomSet reads a TARGETS reply (32-bit atoms).
func atomSet(b []byte) map[xproto.Atom]bool {
	set := map[xproto.Atom]bool{}
	for i := 0; i+4 <= len(b); i += 4 {
		set[xproto.Atom(xgb.Get32(b[i:]))] = true
	}
	return set
}

// convert asks CLIPBOARD's owner for target and returns the data, at most
// maxReadBytes of it.
func (c *x11Clipboard) convert(ctx context.Context, target string, ts xproto.Timestamp) ([]byte, error) {
	clip, prop, tgt := c.mustAtom("CLIPBOARD"), c.mustAtom(x11Property), c.mustAtom(target)
	xproto.ConvertSelection(c.conn, c.win, clip, tgt, prop, ts)
	ev, err := c.await(ctx, func(ev xgb.Event) bool {
		n, ok := ev.(xproto.SelectionNotifyEvent)
		return ok && n.Requestor == c.win && n.Selection == clip
	})
	if err != nil {
		return nil, err
	}
	if ev.(xproto.SelectionNotifyEvent).Property == 0 {
		return nil, errXRefused
	}
	r, err := xproto.GetProperty(c.conn, true, c.win, prop, xproto.GetPropertyTypeAny, 0, maxReadBytes/4).Reply()
	if err != nil {
		return nil, errXClosed
	}
	if r.Type == c.mustAtom("INCR") {
		return c.incr(ctx, prop)
	}
	return r.Value, nil
}

// incr reads a large transfer in chunks (ICCCM INCR): the owner writes a
// chunk each time we delete the property, and an empty one at the end.
// Chunks past maxReadBytes are drained and dropped.
func (c *x11Clipboard) incr(ctx context.Context, prop xproto.Atom) ([]byte, error) {
	var out bytes.Buffer
	for {
		_, err := c.await(ctx, func(ev xgb.Event) bool {
			n, ok := ev.(xproto.PropertyNotifyEvent)
			return ok && n.Window == c.win && n.Atom == prop && n.State == xproto.PropertyNewValue
		})
		if err != nil {
			return nil, err
		}
		r, err := xproto.GetProperty(c.conn, true, c.win, prop, xproto.GetPropertyTypeAny, 0, maxReadBytes/4).Reply()
		if err != nil {
			return nil, errXClosed
		}
		if len(r.Value) == 0 {
			return out.Bytes(), nil
		}
		if keep := maxReadBytes - out.Len(); keep > 0 {
			out.Write(r.Value[:min(len(r.Value), keep)])
		}
	}
}

// replace puts msg on the clipboard in place of the copy e announced, unless
// a newer copy has taken over meanwhile (it gets its own event).
func (c *x11Clipboard) replace(e xfixes.SelectionNotifyEvent, msg string) error {
	clip := c.mustAtom("CLIPBOARD")
	now, err := xproto.GetSelectionOwner(c.conn, clip).Reply()
	if err != nil {
		return err
	}
	if now.Owner != e.Owner {
		return errors.New("a newer copy replaced the scanned content")
	}
	c.owned = []byte(msg)
	// The copy's own timestamp: if anything newer owns CLIPBOARD by now, the
	// server ignores this, and the check below says so.
	xproto.SetSelectionOwner(c.conn, c.win, clip, e.Timestamp)
	got, err := xproto.GetSelectionOwner(c.conn, clip).Reply()
	if err != nil || got.Owner != c.win {
		c.owned = nil
		return errors.New("couldn't take over the clipboard")
	}
	return nil
}

// serve answers an app reading our placeholder.
func (c *x11Clipboard) serve(e xproto.SelectionRequestEvent) {
	prop := e.Property
	if prop == 0 {
		prop = e.Target // obsolete requestors (ICCCM 2.2)
	}
	if !c.answer(e, prop) {
		prop = 0 // refused
	}
	ev := xproto.SelectionNotifyEvent{Time: e.Time, Requestor: e.Requestor, Selection: e.Selection, Target: e.Target, Property: prop}
	xproto.SendEvent(c.conn, false, e.Requestor, 0, string(ev.Bytes()))
}

// answer writes the requested form of the placeholder to the requestor's
// property, and reports whether it could.
func (c *x11Clipboard) answer(e xproto.SelectionRequestEvent, prop xproto.Atom) bool {
	if c.owned == nil || e.Selection != c.mustAtom("CLIPBOARD") {
		return false
	}
	offered := c.placeholderTargets()
	if e.Target == c.mustAtom("TARGETS") {
		buf := make([]byte, 4*len(offered))
		for i, a := range offered {
			xgb.Put32(buf[4*i:], uint32(a))
		}
		xproto.ChangeProperty(c.conn, xproto.PropModeReplace, e.Requestor, prop, xproto.AtomAtom, 32, uint32(len(offered)), buf)
		return true
	}
	for _, a := range offered[1:] {
		if e.Target == a {
			xproto.ChangeProperty(c.conn, xproto.PropModeReplace, e.Requestor, prop, a, 8, uint32(len(c.owned)), c.owned)
			return true
		}
	}
	return false
}

// placeholderTargets is TARGETS for our placeholder: the UTF-8 types, and
// the Latin-1 ones only when the message is plain ASCII.
func (c *x11Clipboard) placeholderTargets() []xproto.Atom {
	ts := []xproto.Atom{c.mustAtom("TARGETS"), c.mustAtom("UTF8_STRING"), c.mustAtom("text/plain;charset=utf-8")}
	if isASCII(c.owned) {
		ts = append(ts, c.mustAtom("STRING"), c.mustAtom("TEXT"), c.mustAtom("text/plain"))
	}
	return ts
}

func isASCII(b []byte) bool {
	for _, x := range b {
		if x >= 0x80 {
			return false
		}
	}
	return true
}

// sourceApp names the app that copied: the focused window's process, when
// that window and the clipboard's owner belong to the same X client. A copy
// from a native Wayland app is owned by the compositor's bridge, which is
// never the focused window, so it stays unnamed rather than misattributed.
func (c *x11Clipboard) sourceApp(owner xproto.Window) events.SourceApp {
	active, ok := c.cardinal(c.root, "_NET_ACTIVE_WINDOW", xproto.AtomWindow)
	if !ok || active == 0 || active&^c.mask != uint32(owner)&^c.mask {
		return events.SourceApp{}
	}
	pid, ok := c.cardinal(xproto.Window(active), "_NET_WM_PID", xproto.AtomCardinal)
	if !ok {
		return events.SourceApp{}
	}
	return processApp(int(pid))
}

// cardinal reads a single 32-bit value of type typ from a window property.
func (c *x11Clipboard) cardinal(w xproto.Window, name string, typ xproto.Atom) (uint32, bool) {
	r, err := xproto.GetProperty(c.conn, false, w, c.mustAtom(name), typ, 0, 1).Reply()
	if err != nil || r.Format != 32 || len(r.Value) < 4 {
		return 0, false
	}
	return xgb.Get32(r.Value), true
}

// processApp names a process by its executable.
func processApp(pid int) events.SourceApp {
	if pid <= 0 {
		return events.SourceApp{}
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return events.SourceApp{}
	}
	return events.SourceApp{Name: exe[strings.LastIndexByte(exe, '/')+1:], Path: exe}
}
