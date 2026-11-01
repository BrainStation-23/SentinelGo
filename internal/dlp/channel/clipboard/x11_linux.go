//go:build linux

package clipboard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// The native X11 backend speaks the X protocol itself (xconn_linux.go, no
// tools): on X11 sessions, and through XWayland on Wayland desktops, whose
// compositors mirror the clipboard to X11 both ways (GNOME, KDE, wlroots).
// XFixes reports every new owner of CLIPBOARD, so each copy, even of the
// same text again, is seen as it happens without polling.
const (
	x11Timeout  = 2 * time.Second  // one selection conversion, or INCR chunk
	x11RetryMax = 30 * time.Second // reconnect backoff cap
	x11Property = "SENTINELGO_CLIPBOARD"
)

var (
	errXTimeout  = errors.New("X11 selection owner didn't answer")
	errXRefused  = errors.New("X11 selection owner refused the conversion")
	errXCanceled = errors.New("X11 clipboard stopped")
)

// textTargets are the text types read from a copy, most preferred first.
var textTargets = []string{"UTF8_STRING", "text/plain;charset=utf-8", "STRING", "text/plain", "TEXT"}

// x11Probe reports whether the session's X server is reachable and has
// XFixes (a seam for tests).
var x11Probe = func() (connected, xfixes bool) {
	x, err := dialXDisplay("")
	if err != nil {
		return false, false
	}
	defer x.close()
	return true, x.initXFixes() == nil
}

// runX11 watches the clipboard until ctx ends, reconnecting when the X
// server goes away (XWayland can be restarted under a running session).
func runX11(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	log.Printf("DLP helper: clipboard via x11-native")
	backoff, failing := time.Second, false
	for {
		c, err := dialX11()
		if err == nil {
			if failing {
				log.Printf("DLP helper: X11 clipboard reconnected")
			}
			backoff, failing = time.Second, false
			err = c.watch(ctx, p, sink)
			c.x.close()
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

// x11Clipboard watches CLIPBOARD on one connection. Only the goroutine that
// calls watch uses it.
type x11Clipboard struct {
	x     *xConn
	win   uint32 // our unmapped window: requestor and owner
	atoms map[string]uint32
	held  []any // events put aside while waiting for a conversion

	owned []byte // the placeholder while we own CLIPBOARD
}

func dialX11() (*x11Clipboard, error) {
	x, err := dialXDisplay("")
	if err != nil {
		return nil, err
	}
	c, err := newX11Clipboard(x)
	if err != nil {
		x.close()
		return nil, err
	}
	return c, nil
}

func newX11Clipboard(x *xConn) (*x11Clipboard, error) {
	if err := x.initXFixes(); err != nil {
		return nil, err
	}
	win, err := x.createInputWindow(eventMaskPropChange)
	if err != nil {
		return nil, err
	}
	c := &x11Clipboard{x: x, win: win, atoms: map[string]uint32{}}
	for _, name := range append([]string{"CLIPBOARD", "TARGETS", "INCR", x11Property, hintTarget, "_NET_ACTIVE_WINDOW", "_NET_WM_PID"}, textTargets...) {
		a, err := x.internAtom(name)
		if err != nil {
			return nil, err
		}
		c.atoms[name] = a
	}
	if err := x.watchSelectionOwner(win, c.atoms["CLIPBOARD"]); err != nil {
		return nil, err
	}
	return c, nil
}

// watch handles events until the connection fails or ctx ends.
func (c *x11Clipboard) watch(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	for {
		ev, err := c.next(ctx)
		if err != nil {
			return err
		}
		switch e := ev.(type) {
		case xSelectionRequest:
			c.serve(e)
		case xSelectionClear:
			c.owned = nil // a newer copy took over from our placeholder
		case xOwnerChange:
			if e.owner == c.win || e.owner == 0 || c.newerCopyWaiting() {
				continue // our placeholder, the clipboard emptied, or already replaced
			}
			if err := c.onCopy(ctx, p, sink, e); errors.Is(err, errXConnClosed) || ctx.Err() != nil {
				return err
			}
		}
	}
}

// next returns the next event, put-aside ones first.
func (c *x11Clipboard) next(ctx context.Context) (any, error) {
	if len(c.held) > 0 {
		ev := c.held[0]
		c.held = c.held[1:]
		return ev, nil
	}
	ev, err := c.x.nextEvent(ctx.Done(), time.Time{})
	if errors.Is(err, errXCanceled) {
		return nil, ctx.Err()
	}
	return ev, err
}

// newerCopyWaiting reports whether another copy has been announced after
// the one being handled: reading now would get that copy's content, which
// is then handled once, for its own announcement.
func (c *x11Clipboard) newerCopyWaiting() bool {
	isCopy := func(ev any) bool {
		e, ok := ev.(xOwnerChange)
		return ok && e.owner != c.win && e.owner != 0
	}
	for _, ev := range c.held {
		if isCopy(ev) {
			return true
		}
	}
	return c.x.eventQueued(isCopy)
}

// await waits for an event match accepts. Meanwhile it answers requests for
// our placeholder (an app waiting on us would otherwise stall) and puts
// every other event aside for watch.
func (c *x11Clipboard) await(ctx context.Context, match func(any) bool) (any, error) {
	deadline := time.Now().Add(x11Timeout)
	for {
		ev, err := c.x.nextEvent(ctx.Done(), deadline)
		if errors.Is(err, errXCanceled) {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if r, ok := ev.(xSelectionRequest); ok {
			c.serve(r)
			continue
		}
		if match(ev) {
			return ev, nil
		}
		c.held = append(c.held, ev)
	}
}

// onCopy scans a new copy and acts on it.
func (c *x11Clipboard) onCopy(ctx context.Context, p *policy.Compiled, sink channel.EventSink, e xOwnerChange) error {
	targets, err := c.convert(ctx, c.atoms["TARGETS"], e.timestamp)
	if errors.Is(err, errXConnClosed) || ctx.Err() != nil {
		return err
	}
	offered := atomSet(targets) // empty when the owner can't list them: try UTF8_STRING anyway
	if p.Modules.Clipboard.IgnoreConcealed && offered[c.atoms[hintTarget]] {
		return nil
	}
	target := c.atoms["UTF8_STRING"]
	if len(offered) > 0 {
		target = 0
		for _, t := range textTargets {
			if offered[c.atoms[t]] {
				target = c.atoms[t]
				break
			}
		}
		if target == 0 {
			return nil // not text (an image, files)
		}
	}
	text, err := c.convert(ctx, target, e.timestamp)
	if err != nil || len(text) == 0 {
		return err
	}
	enforce(p, sink, text, c.sourceApp(e.owner), func(msg string) error {
		return c.replace(e, msg)
	})
	return nil
}

// atomSet reads a TARGETS reply (32-bit atoms).
func atomSet(b []byte) map[uint32]bool {
	set := map[uint32]bool{}
	for i := 0; i+4 <= len(b); i += 4 {
		set[binary.LittleEndian.Uint32(b[i:])] = true
	}
	return set
}

// convert asks CLIPBOARD's owner for target and returns the data, at most
// maxReadBytes of it.
func (c *x11Clipboard) convert(ctx context.Context, target, ts uint32) ([]byte, error) {
	clip, prop := c.atoms["CLIPBOARD"], c.atoms[x11Property]
	if err := c.x.convertSelection(c.win, clip, target, prop, ts); err != nil {
		return nil, err
	}
	ev, err := c.await(ctx, func(ev any) bool {
		n, ok := ev.(xSelectionNotify)
		return ok && n.requestor == c.win && n.selection == clip
	})
	if err != nil {
		return nil, err
	}
	if ev.(xSelectionNotify).property == 0 {
		return nil, errXRefused
	}
	r, err := c.x.getProperty(true, c.win, prop, anyPropertyType, maxReadBytes)
	if err != nil {
		return nil, err
	}
	if r.typ == c.atoms["INCR"] {
		return c.incr(ctx, prop)
	}
	return r.value, nil
}

// incr reads a large transfer in chunks (ICCCM INCR): the owner writes a
// chunk each time we delete the property, and an empty one at the end.
// Chunks past maxReadBytes are drained and dropped.
func (c *x11Clipboard) incr(ctx context.Context, prop uint32) ([]byte, error) {
	var out bytes.Buffer
	for {
		_, err := c.await(ctx, func(ev any) bool {
			n, ok := ev.(xPropertyNotify)
			return ok && n.window == c.win && n.atom == prop && !n.deleted
		})
		if err != nil {
			return nil, err
		}
		r, err := c.x.getProperty(true, c.win, prop, anyPropertyType, maxReadBytes)
		if err != nil {
			return nil, err
		}
		if len(r.value) == 0 {
			return out.Bytes(), nil
		}
		if keep := maxReadBytes - out.Len(); keep > 0 {
			out.Write(r.value[:min(len(r.value), keep)])
		}
	}
}

// replace puts msg on the clipboard in place of the copy e announced, unless
// a newer copy has taken over meanwhile (it gets its own event).
func (c *x11Clipboard) replace(e xOwnerChange, msg string) error {
	clip := c.atoms["CLIPBOARD"]
	if c.newerCopyWaiting() {
		return errors.New("a newer copy replaced the scanned content")
	}
	if now, err := c.x.selectionOwner(clip); err != nil || now != e.owner {
		return errors.New("a newer copy replaced the scanned content")
	}
	c.owned = []byte(msg)
	// The copy's own timestamp: if anything newer owns CLIPBOARD by now, the
	// server ignores this, and the check below says so.
	if err := c.x.setSelectionOwner(c.win, clip, e.timestamp); err != nil {
		c.owned = nil
		return err
	}
	if got, err := c.x.selectionOwner(clip); err != nil || got != c.win {
		c.owned = nil
		return errors.New("couldn't take over the clipboard")
	}
	return nil
}

// serve answers an app reading our placeholder.
func (c *x11Clipboard) serve(e xSelectionRequest) {
	prop := e.property
	if prop == 0 {
		prop = e.target // obsolete requestors (ICCCM 2.2)
	}
	if !c.answer(e, prop) {
		prop = 0 // refused
	}
	_ = c.x.sendSelectionNotify(e, prop)
}

// answer writes the requested form of the placeholder to the requestor's
// property, and reports whether it could.
func (c *x11Clipboard) answer(e xSelectionRequest, prop uint32) bool {
	if c.owned == nil || e.selection != c.atoms["CLIPBOARD"] {
		return false
	}
	offered := c.placeholderTargets()
	if e.target == c.atoms["TARGETS"] {
		buf := make([]byte, 0, 4*len(offered))
		for _, a := range offered {
			buf = binary.LittleEndian.AppendUint32(buf, a)
		}
		return c.x.changeProperty(e.requestor, prop, atomAtom, 32, buf) == nil
	}
	for _, a := range offered[1:] {
		if e.target == a {
			return c.x.changeProperty(e.requestor, prop, a, 8, c.owned) == nil
		}
	}
	return false
}

// placeholderTargets is TARGETS for our placeholder: the UTF-8 types, and
// the Latin-1 ones only when the message is plain ASCII.
func (c *x11Clipboard) placeholderTargets() []uint32 {
	ts := []uint32{c.atoms["TARGETS"], c.atoms["UTF8_STRING"], c.atoms["text/plain;charset=utf-8"]}
	if isASCII(c.owned) {
		ts = append(ts, c.atoms["STRING"], c.atoms["TEXT"], c.atoms["text/plain"])
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
func (c *x11Clipboard) sourceApp(owner uint32) events.SourceApp {
	active, ok := c.cardinal(c.x.root, "_NET_ACTIVE_WINDOW", atomWindow)
	if !ok || active == 0 || active&^c.x.idMask != owner&^c.x.idMask {
		return events.SourceApp{}
	}
	pid, ok := c.cardinal(active, "_NET_WM_PID", atomCardinal)
	if !ok || pid == 0 || pid > 1<<22 { // Linux's pid_max ceiling
		return events.SourceApp{}
	}
	return processApp(int(pid))
}

// cardinal reads a single 32-bit value of type typ from a window property.
func (c *x11Clipboard) cardinal(w uint32, name string, typ uint32) (uint32, bool) {
	r, err := c.x.getProperty(false, w, c.atoms[name], typ, 4)
	if err != nil || r.format != 32 || len(r.value) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(r.value), true
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
