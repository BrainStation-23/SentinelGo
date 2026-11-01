package clipboard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"

	"sentinelgo/internal/dlp/events"
)

// These tests run the x11-native backend against a private Xvfb (skipped
// where Xvfb isn't installed), with a second X client in the test copying
// like an app would. They never touch the desktop's own clipboard.

// startXvfb starts Xvfb on display (":N"), or on a free one when display is
// empty, and returns the display. It is stopped when the test ends; stop
// stops it earlier.
func startXvfb(t *testing.T, display string) (disp string, stop func()) {
	t.Helper()
	bin, err := exec.LookPath("Xvfb")
	if err != nil {
		t.Skip("Xvfb not installed")
	}
	args := []string{"-nolisten", "tcp", "-noreset", "-screen", "0", "320x200x24"}
	cmd := exec.Command(bin, args...) // #nosec G204 -- test helper
	var r *os.File
	if display == "" {
		var w *os.File
		if r, w, err = os.Pipe(); err != nil {
			t.Fatal(err)
		}
		cmd.Args = append(cmd.Args, "-displayfd", "3")
		cmd.ExtraFiles = []*os.File{w}
		defer func() { _ = w.Close() }()
	} else {
		cmd.Args = append(cmd.Args, display)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}
	t.Cleanup(stop)

	if display == "" {
		line := make(chan string, 1)
		go func() {
			s, _ := bufio.NewReader(r).ReadString('\n')
			line <- strings.TrimSpace(s)
		}()
		select {
		case n := <-line:
			if n == "" {
				t.Fatal("Xvfb didn't report a display")
			}
			display = ":" + n
		case <-time.After(10 * time.Second):
			t.Fatal("Xvfb didn't start")
		}
	}
	waitFor(t, "Xvfb on "+display, func() bool {
		c, err := xgb.NewConnDisplay(display)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	return display, stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// useXvfb points the channel at a fresh Xvfb, X11 only.
func useXvfb(t *testing.T) (display string, stop func()) {
	t.Helper()
	display, stop = startXvfb(t, "")
	t.Setenv("DISPLAY", display)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XAUTHORITY", filepath.Join(t.TempDir(), "none")) // Xvfb runs without access control
	return display, stop
}

// lockedSink records events from the channel's goroutine.
type lockedSink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (s *lockedSink) Emit(ev events.Event) { s.mu.Lock(); s.evs = append(s.evs, ev); s.mu.Unlock() }

func (s *lockedSink) events() []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.Event(nil), s.evs...)
}

// xApp is another X client that copies, and reads what's on the clipboard.
type xApp struct {
	t     *testing.T
	conn  *xgb.Conn
	root  xproto.Window
	win   xproto.Window
	atoms map[string]xproto.Atom

	mu      sync.Mutex
	data    []byte
	targets []string
	incr    map[xproto.Window]incrTransfer // in progress, by requestor
	notify  chan xproto.SelectionNotifyEvent
}

// incrTransfer is what's left to send of an INCR transfer, and where.
type incrTransfer struct {
	prop xproto.Atom
	rest []byte
}

const (
	testIncrThreshold = 256 << 10 // copies larger than this are sent with INCR
	testIncrChunk     = 64 << 10
)

func newXApp(t *testing.T, display string) *xApp {
	t.Helper()
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	screen := xproto.Setup(conn).DefaultScreen(conn)
	win, _ := xproto.NewWindowId(conn)
	if err := xproto.CreateWindowChecked(conn, 0, win, screen.Root, 0, 0, 1, 1, 0,
		xproto.WindowClassInputOnly, screen.RootVisual, 0, nil).Check(); err != nil {
		t.Fatal(err)
	}
	a := &xApp{t: t, conn: conn, root: screen.Root, win: win, atoms: map[string]xproto.Atom{},
		incr: map[xproto.Window]incrTransfer{}, notify: make(chan xproto.SelectionNotifyEvent, 1)}
	for _, n := range []string{"CLIPBOARD", "TARGETS", "INCR", "UTF8_STRING", "image/png", hintTarget, "APP_PROP", "_NET_ACTIVE_WINDOW", "_NET_WM_PID"} {
		r, err := xproto.InternAtom(conn, false, uint16(len(n)), n).Reply()
		if err != nil {
			t.Fatal(err)
		}
		a.atoms[n] = r.Atom
	}
	go a.loop()
	return a
}

// copy makes the app own CLIPBOARD with data offered as targets.
func (a *xApp) copy(data string, targets ...string) {
	a.mu.Lock()
	a.data, a.targets = []byte(data), targets
	a.mu.Unlock()
	xproto.SetSelectionOwner(a.conn, a.win, a.atoms["CLIPBOARD"], xproto.TimeCurrentTime)
	if _, err := xproto.GetSelectionOwner(a.conn, a.atoms["CLIPBOARD"]).Reply(); err != nil {
		a.t.Fatal(err) // also a round trip: the owner change has happened
	}
}

// focus marks the app's window as the focused one, as a window manager does.
func (a *xApp) focus() {
	pid := make([]byte, 4)
	xgb.Put32(pid, uint32(os.Getpid()))
	xproto.ChangeProperty(a.conn, xproto.PropModeReplace, a.win, a.atoms["_NET_WM_PID"], xproto.AtomCardinal, 32, 1, pid)
	w := make([]byte, 4)
	xgb.Put32(w, uint32(a.win))
	xproto.ChangeProperty(a.conn, xproto.PropModeReplace, a.root, a.atoms["_NET_ACTIVE_WINDOW"], xproto.AtomWindow, 32, 1, w)
}

// clipboard reads the clipboard's text as another app would.
func (a *xApp) clipboard() string {
	xproto.ConvertSelection(a.conn, a.win, a.atoms["CLIPBOARD"], a.atoms["UTF8_STRING"], a.atoms["APP_PROP"], xproto.TimeCurrentTime)
	select {
	case n := <-a.notify:
		if n.Property == 0 {
			return "<refused>"
		}
	case <-time.After(5 * time.Second):
		return "<timeout>"
	}
	r, err := xproto.GetProperty(a.conn, true, a.win, a.atoms["APP_PROP"], xproto.GetPropertyTypeAny, 0, 1<<20).Reply()
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(r.Value)
}

func (a *xApp) loop() {
	for {
		ev, xerr := a.conn.WaitForEvent()
		if ev == nil && xerr == nil {
			return
		}
		switch e := ev.(type) {
		case xproto.SelectionRequestEvent:
			a.serve(e)
		case xproto.PropertyNotifyEvent:
			a.nextChunk(e)
		case xproto.SelectionNotifyEvent:
			select {
			case a.notify <- e:
			default:
			}
		}
	}
}

func (a *xApp) serve(e xproto.SelectionRequestEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prop := e.Property
	offered := false
	for _, n := range a.targets {
		offered = offered || a.atoms[n] == e.Target
	}
	switch {
	case e.Target == a.atoms["TARGETS"]:
		buf := make([]byte, 4*(len(a.targets)+1))
		xgb.Put32(buf, uint32(a.atoms["TARGETS"]))
		for i, n := range a.targets {
			xgb.Put32(buf[4*(i+1):], uint32(a.atoms[n]))
		}
		xproto.ChangeProperty(a.conn, xproto.PropModeReplace, e.Requestor, prop, xproto.AtomAtom, 32, uint32(len(a.targets)+1), buf)
	case offered && len(a.data) > testIncrThreshold:
		// Watch the requestor's property; each deletion asks for a chunk.
		xproto.ChangeWindowAttributes(a.conn, e.Requestor, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange})
		a.incr[e.Requestor] = incrTransfer{prop: prop, rest: a.data}
		size := make([]byte, 4)
		xgb.Put32(size, uint32(len(a.data)))
		xproto.ChangeProperty(a.conn, xproto.PropModeReplace, e.Requestor, prop, a.atoms["INCR"], 32, 1, size)
	case offered:
		xproto.ChangeProperty(a.conn, xproto.PropModeReplace, e.Requestor, prop, e.Target, 8, uint32(len(a.data)), a.data)
	default:
		prop = 0
	}
	ev := xproto.SelectionNotifyEvent{Time: e.Time, Requestor: e.Requestor, Selection: e.Selection, Target: e.Target, Property: prop}
	xproto.SendEvent(a.conn, false, e.Requestor, 0, string(ev.Bytes()))
}

// nextChunk sends the next INCR chunk once the requestor has taken the last
// (deleted the property); an empty chunk ends the transfer.
func (a *xApp) nextChunk(e xproto.PropertyNotifyEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tr, ok := a.incr[e.Window]
	if !ok || e.Atom != tr.prop || e.State != xproto.PropertyDelete {
		return
	}
	chunk := tr.rest[:min(len(tr.rest), testIncrChunk)]
	if len(chunk) == 0 {
		delete(a.incr, e.Window)
	} else {
		tr.rest = tr.rest[len(chunk):]
		a.incr[e.Window] = tr
	}
	xproto.ChangeProperty(a.conn, xproto.PropModeReplace, e.Window, tr.prop, a.atoms["UTF8_STRING"], 8, uint32(len(chunk)), chunk)
}

// runChannel runs the clipboard channel until the test ends.
func runChannel(t *testing.T, policies string, ignoreConcealed bool) *lockedSink {
	t.Helper()
	p := compile(t, policies)
	p.Modules.Clipboard.IgnoreConcealed = ignoreConcealed
	if b, c := pickBackend(context.Background()); b.name != "x11-native" {
		t.Fatalf("backend %q (%s), want x11-native", b.name, c)
	}
	s := &lockedSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New().Run(ctx, p, s) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v", err)
		}
	})
	return s
}

const placeholder = "Blocked by SentinelOps: credit card"

func TestX11_BlockMonitorAndRepeats(t *testing.T) {
	display, _ := useXvfb(t)
	app := newXApp(t, display)
	s := runChannel(t, blockCards+","+monitorFalcon, false)
	time.Sleep(100 * time.Millisecond) // let the channel subscribe

	app.focus()
	app.copy("card 4111 1111 1111 1111", "UTF8_STRING")
	waitFor(t, "the card to be replaced", func() bool { return app.clipboard() == placeholder })
	evs := s.events()
	if len(evs) != 1 || evs[0].Action != events.ActionBlocked {
		t.Fatalf("events = %+v", evs)
	}
	if exe, _ := os.Executable(); evs[0].SourceApp.Path != exe {
		t.Errorf("source app = %+v, want this process %s", evs[0].SourceApp, exe)
	}

	// Monitored: recorded, left on the clipboard. The same text copied again
	// is a new copy, and is recorded again.
	app.copy("project falcon", "UTF8_STRING")
	waitFor(t, "the monitor event", func() bool { return len(s.events()) == 2 })
	app.copy("project falcon", "UTF8_STRING")
	waitFor(t, "the repeat's event", func() bool { return len(s.events()) == 3 })
	if got := app.clipboard(); got != "project falcon" {
		t.Errorf("monitored copy changed to %q", got)
	}
	for _, ev := range s.events()[1:] {
		if ev.Action != events.ActionMonitored {
			t.Errorf("event %+v, want monitored", ev)
		}
	}

	// The secret copied again after the placeholder is blocked again.
	app.copy("4111111111111111", "UTF8_STRING")
	waitFor(t, "the re-copied card to be replaced", func() bool { return app.clipboard() == placeholder })
}

// A copy owned by another client than the focused window (the compositor's
// bridge, for a Wayland app) isn't attributed to the focused app.
func TestX11_SourceNotMisattributed(t *testing.T) {
	display, _ := useXvfb(t)
	focused, copier := newXApp(t, display), newXApp(t, display)
	s := runChannel(t, blockCards, false)
	time.Sleep(100 * time.Millisecond)

	focused.focus()
	copier.copy("4111111111111111", "UTF8_STRING")
	waitFor(t, "the event", func() bool { return len(s.events()) == 1 })
	if src := s.events()[0].SourceApp; src != (events.SourceApp{}) {
		t.Errorf("source = %+v, want unknown", src)
	}
}

func TestX11_ConcealedAndNonText(t *testing.T) {
	display, _ := useXvfb(t)
	app := newXApp(t, display)
	s := runChannel(t, blockCards, true)
	time.Sleep(100 * time.Millisecond)

	app.copy("4111111111111111", "UTF8_STRING", hintTarget)
	app.copy("4111111111111111", "image/png")
	app.copy("project falcon 4111111111111111", "UTF8_STRING") // a marker: handled after both
	waitFor(t, "the marker copy", func() bool { return len(s.events()) >= 1 })
	if evs := s.events(); len(evs) != 1 {
		t.Errorf("events = %d, want only the marker's (concealed and image skipped)", len(evs))
	}
}

// A copy above the X request size limit arrives in INCR chunks.
func TestX11_LargeCopy(t *testing.T) {
	display, _ := useXvfb(t)
	app := newXApp(t, display)
	s := runChannel(t, blockCards, false)
	time.Sleep(100 * time.Millisecond)

	big := "4111 1111 1111 1111 " + strings.Repeat("x", 1<<20)
	app.copy(big, "UTF8_STRING")
	waitFor(t, "the large copy to be replaced", func() bool { return app.clipboard() == placeholder })
	if evs := s.events(); len(evs) != 1 || evs[0].ContentLength != len(big) {
		t.Errorf("events = %+v, want one with the full length %d", evs, len(big))
	}
}

// When the X server goes away the channel keeps running and reconnects.
func TestX11_Reconnects(t *testing.T) {
	display, stop := useXvfb(t)
	s := runChannel(t, blockCards, false)
	time.Sleep(100 * time.Millisecond)

	stop()
	time.Sleep(200 * time.Millisecond)
	startXvfb(t, display)
	app := newXApp(t, display)
	waitFor(t, "a copy to be blocked after the restart", func() bool {
		app.copy(fmt.Sprintf("4111111111111111 %d", time.Now().UnixNano()), "UTF8_STRING")
		time.Sleep(100 * time.Millisecond)
		return app.clipboard() == placeholder
	})
	if len(s.events()) == 0 {
		t.Error("no event after reconnecting")
	}
}

// The probe tells a reachable X server with XFixes from none.
func TestX11Probe(t *testing.T) {
	useXvfb(t)
	if c, f := x11Probe(); !c || !f {
		t.Errorf("Xvfb: connected %v, xfixes %v", c, f)
	}
	t.Setenv("DISPLAY", ":999")
	if c, _ := x11Probe(); c {
		t.Error("connected to a display that doesn't exist")
	}
}
