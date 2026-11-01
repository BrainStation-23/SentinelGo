package clipboard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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
			_ = cmd.Process.Signal(syscall.SIGTERM) // lets Xvfb remove its socket and lock
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
		x, err := dialXDisplay(display)
		if err != nil {
			return false
		}
		x.close()
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
	x     *xConn
	win   uint32
	atoms map[string]uint32
	done  chan struct{}

	mu       sync.Mutex
	data     []byte
	targets  []string
	listed   int                     // TARGETS requests served
	incr     map[uint32]incrTransfer // in progress, by requestor
	notified chan xSelectionNotify
}

// incrTransfer is what's left to send of an INCR transfer, and where.
type incrTransfer struct {
	prop uint32
	rest []byte
}

const (
	testIncrThreshold = 128 << 10 // copies larger than this are sent with INCR
	testIncrChunk     = 64 << 10
)

func newXApp(t *testing.T, display string) *xApp {
	t.Helper()
	x, err := dialXDisplay(display)
	if err != nil {
		t.Fatal(err)
	}
	win, err := x.createInputWindow(0)
	if err != nil {
		t.Fatal(err)
	}
	a := &xApp{t: t, x: x, win: win, atoms: map[string]uint32{}, done: make(chan struct{}),
		incr: map[uint32]incrTransfer{}, notified: make(chan xSelectionNotify, 1)}
	for _, n := range []string{"CLIPBOARD", "TARGETS", "INCR", "UTF8_STRING", "image/png", hintTarget, "APP_PROP", "_NET_ACTIVE_WINDOW", "_NET_WM_PID"} {
		if a.atoms[n], err = x.internAtom(n); err != nil {
			t.Fatal(err)
		}
	}
	go a.loop()
	t.Cleanup(func() { close(a.done); x.close() })
	return a
}

// copy makes the app own CLIPBOARD with data offered as targets.
func (a *xApp) copy(data string, targets ...string) {
	a.mu.Lock()
	a.data, a.targets = []byte(data), targets
	a.mu.Unlock()
	if err := a.x.setSelectionOwner(a.win, a.atoms["CLIPBOARD"], currentTime); err != nil {
		a.t.Fatal(err)
	}
	if _, err := a.x.selectionOwner(a.atoms["CLIPBOARD"]); err != nil {
		a.t.Fatal(err) // also a round trip: the owner change has happened
	}
}

// listedCount is how many times the channel asked for the copy's types.
func (a *xApp) listedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.listed
}

// focus marks the app's window as the focused one, as a window manager does.
func (a *xApp) focus() {
	pid := binary.LittleEndian.AppendUint32(nil, uint32(os.Getpid())) // #nosec G115 -- a pid
	_ = a.x.changeProperty(a.win, a.atoms["_NET_WM_PID"], atomCardinal, 32, pid)
	w := binary.LittleEndian.AppendUint32(nil, a.win)
	_ = a.x.changeProperty(a.x.root, a.atoms["_NET_ACTIVE_WINDOW"], atomWindow, 32, w)
}

// clipboard reads the clipboard's text as another app would.
func (a *xApp) clipboard() string { return a.clipboardAs("UTF8_STRING") }

// clipboardAs reads the clipboard in the given type.
func (a *xApp) clipboardAs(target string) string {
	if err := a.x.convertSelection(a.win, a.atoms["CLIPBOARD"], a.atoms[target], a.atoms["APP_PROP"], currentTime); err != nil {
		return "<" + err.Error() + ">"
	}
	select {
	case n := <-a.notified:
		if n.property == 0 {
			return "<refused>"
		}
	case <-time.After(5 * time.Second):
		return "<timeout>"
	}
	r, err := a.x.getProperty(true, a.win, a.atoms["APP_PROP"], anyPropertyType, 1<<20)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(r.value)
}

func (a *xApp) loop() {
	for {
		ev, err := a.x.nextEvent(a.done, time.Time{})
		if err != nil {
			return
		}
		switch e := ev.(type) {
		case xSelectionRequest:
			a.serve(e)
		case xPropertyNotify:
			a.nextChunk(e)
		case xSelectionNotify:
			select {
			case a.notified <- e:
			default:
			}
		}
	}
}

func (a *xApp) serve(e xSelectionRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prop := e.property
	offered := false
	for _, n := range a.targets {
		offered = offered || a.atoms[n] == e.target
	}
	switch {
	case e.target == a.atoms["TARGETS"]:
		buf := binary.LittleEndian.AppendUint32(nil, a.atoms["TARGETS"])
		for _, n := range a.targets {
			buf = binary.LittleEndian.AppendUint32(buf, a.atoms[n])
		}
		_ = a.x.changeProperty(e.requestor, prop, atomAtom, 32, buf)
		a.listed++
	case offered && len(a.data) > testIncrThreshold:
		// Watch the requestor's property; each deletion asks for a chunk.
		_ = a.x.selectWindowEvents(e.requestor, eventMaskPropChange)
		a.incr[e.requestor] = incrTransfer{prop: prop, rest: a.data}
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(a.data))) // #nosec G115 -- test data, a few MB
		_ = a.x.changeProperty(e.requestor, prop, a.atoms["INCR"], 32, size)
	case offered:
		_ = a.x.changeProperty(e.requestor, prop, e.target, 8, a.data)
	default:
		prop = 0
	}
	_ = a.x.sendSelectionNotify(e, prop)
}

// nextChunk sends the next INCR chunk once the requestor has taken the last
// (deleted the property); an empty chunk ends the transfer.
func (a *xApp) nextChunk(e xPropertyNotify) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tr, ok := a.incr[e.window]
	if !ok || e.atom != tr.prop || !e.deleted {
		return
	}
	chunk := tr.rest[:min(len(tr.rest), testIncrChunk)]
	if len(chunk) == 0 {
		delete(a.incr, e.window)
	} else {
		tr.rest = tr.rest[len(chunk):]
		a.incr[e.window] = tr
	}
	_ = a.x.changeProperty(e.window, tr.prop, a.atoms["UTF8_STRING"], 8, chunk)
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

	// The placeholder is only text: other types are refused.
	app.copy("card 4111 1111 1111 1111", "UTF8_STRING")
	waitFor(t, "the card to be replaced again", func() bool { return app.clipboard() == placeholder })
	if got := app.clipboardAs("image/png"); got != "<refused>" {
		t.Errorf("placeholder as image/png = %q, want refused", got)
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

	// Each copy is let through only once the channel has looked at it (asked
	// for its types), so it never reads the next one's content.
	app.copy("4111111111111111", "UTF8_STRING", hintTarget)
	waitFor(t, "the concealed copy to be looked at", func() bool { return app.listedCount() == 1 })
	app.copy("4111111111111111", "image/png")
	waitFor(t, "the image to be looked at", func() bool { return app.listedCount() == 2 })
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

func TestParseDisplay(t *testing.T) {
	tests := []struct {
		in, host, number string
		screen           int
		ok               bool
	}{
		{":0", "", "0", 0, true},
		{":1.2", "", "1", 2, true},
		{"unix:3", "unix", "3", 0, true},
		{"host.example:10.0", "host.example", "10", 0, true},
		{"", "", "", 0, false},
		{"0", "", "", 0, false},
		{":x", "", "", 0, false},
		{":-1", "", "", 0, false},
		{":0.x", "", "", 0, false},
	}
	for _, tt := range tests {
		host, number, screen, err := parseDisplay(tt.in)
		if (err == nil) != tt.ok || (tt.ok && (host != tt.host || number != tt.number || screen != tt.screen)) {
			t.Errorf("parseDisplay(%q) = %q %q %d %v", tt.in, host, number, screen, err)
		}
	}
}

// xauthEntry encodes one Xauthority entry.
func xauthEntry(family uint16, addr, number, name string, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, family)
	for _, f := range [][]byte{[]byte(addr), []byte(number), []byte(name), data} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f))) // #nosec G115 -- short test fields
		b = append(b, f...)
	}
	return b
}

func TestFindCookie(t *testing.T) {
	cookie := []byte("0123456789abcdef")
	other := []byte("fedcba9876543210")
	file := bytes.Join([][]byte{
		xauthEntry(familyLocal, "otherhost", "0", "MIT-MAGIC-COOKIE-1", other),
		xauthEntry(familyLocal, "myhost", "5", "MIT-MAGIC-COOKIE-1", other),
		xauthEntry(familyLocal, "myhost", "0", "XDM-AUTHORIZATION-1", other),
		xauthEntry(familyLocal, "myhost", "", "MIT-MAGIC-COOKIE-1", cookie), // XWayland: any display
	}, nil)
	if name, data := findCookie(bytes.NewReader(file), true, "myhost", "0"); name != "MIT-MAGIC-COOKIE-1" || !bytes.Equal(data, cookie) {
		t.Errorf("local: %q %x", name, data)
	}
	if _, data := findCookie(bytes.NewReader(file), true, "myhost", "5"); !bytes.Equal(data, other) {
		t.Errorf("display 5: %x, want its own entry", data)
	}
	if name, _ := findCookie(bytes.NewReader(file), false, "myhost", "0"); name != "" {
		t.Errorf("remote display matched a local entry: %q", name)
	}
	wild := xauthEntry(familyWild, "\x00\x01", "", "MIT-MAGIC-COOKIE-1", cookie)
	if _, data := findCookie(bytes.NewReader(wild), false, "myhost", "7"); !bytes.Equal(data, cookie) {
		t.Errorf("wild entry: %x", data)
	}
	if name, _ := findCookie(bytes.NewReader(file[:len(file)-3]), true, "myhost", "0"); name != "" {
		t.Errorf("truncated file gave %q", name)
	}
}

// The real Xauthority lookup, against a file named by XAUTHORITY.
func TestXauthCookie(t *testing.T) {
	host, _ := os.Hostname()
	cookie := []byte("0123456789abcdef")
	path := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(path, xauthEntry(familyLocal, host, "", "MIT-MAGIC-COOKIE-1", cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XAUTHORITY", path)
	if _, data := xauthCookie("", "0"); !bytes.Equal(data, cookie) {
		t.Errorf("cookie = %x", data)
	}
	t.Setenv("XAUTHORITY", filepath.Join(t.TempDir(), "missing"))
	if name, _ := xauthCookie("", "0"); name != "" {
		t.Errorf("missing file gave %q", name)
	}
}

// A request the server rejects reports the X error.
func TestXConn_ServerError(t *testing.T) {
	display, _ := useXvfb(t)
	x, err := dialXDisplay(display)
	if err != nil {
		t.Fatal(err)
	}
	defer x.close()
	if err := x.initXFixes(); err != nil {
		t.Fatal(err)
	}
	err = x.watchSelectionOwner(0x1fffffff, 1) // no such window
	var xe *xError
	if !errors.As(err, &xe) || !strings.Contains(err.Error(), "X error") {
		t.Fatalf("err = %v, want an X error", err)
	}
	// The connection stays usable after an error.
	if _, err := x.internAtom("CLIPBOARD"); err != nil {
		t.Errorf("after an error: %v", err)
	}
	x.close()
	if _, err := x.internAtom("CLIPBOARD"); !errors.Is(err, errXConnClosed) {
		t.Errorf("after close: %v, want errXConnClosed", err)
	}
}
