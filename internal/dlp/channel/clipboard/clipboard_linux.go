//go:build linux

package clipboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// On Linux the channel picks the first of these that works in the session:
//
//   - x11-native: the X protocol in pure Go (x11_linux.go), on X11 sessions
//     and, through XWayland, on Wayland desktops (GNOME, KDE, wlroots
//     compositors mirror the clipboard to X11). Event driven, no tools.
//   - wayland: wl-paste / wl-copy (wl-clipboard), only when the compositor
//     offers the data-control protocol (wlprobe_linux.go). Without it (GNOME)
//     wl-clipboard opens a window and grabs focus on every call.
//   - x11: xclip, else xsel, for an X server without XFixes.
//
// The tool backends poll every pollInterval and find new copies by comparing
// the text's hash. A copy marked by a password manager
// (x-kde-passwordManagerHint, set by KeePassXC and KDE apps) is ignored when
// the policy says so.
const (
	pollInterval = 400 * time.Millisecond
	toolTimeout  = 2 * time.Second
	maxReadBytes = 16 << 20
	hintTarget   = "x-kde-passwordManagerHint"
)

// backend is one way to reach the session's clipboard.
type backend struct {
	name    string
	native  bool     // x11-native: no tools, see x11_linux.go
	read    []string // prints the clipboard text
	targets []string // prints the offered MIME types/targets, one per line
	write   []string // reads the new text on stdin and owns the clipboard
}

var (
	x11Native = backend{name: "x11-native", native: true}
	wayland   = backend{
		name:    "wayland",
		read:    []string{"wl-paste", "--no-newline", "--type", "text"}, // any text type the app offers
		targets: []string{"wl-paste", "--list-types"},
		write:   []string{"wl-copy", "--type", "text/plain;charset=utf-8"},
	}
	xclip = backend{
		name:    "x11",
		read:    []string{"xclip", "-selection", "clipboard", "-o", "-t", "UTF8_STRING"},
		targets: []string{"xclip", "-selection", "clipboard", "-o", "-t", "TARGETS"},
		write:   []string{"xclip", "-selection", "clipboard", "-i"},
	}
	xsel = backend{
		name:  "x11",
		read:  []string{"xsel", "--clipboard", "--output"},
		write: []string{"xsel", "--clipboard", "--input"},
	}
)

// lookPath and run are seams for tests.
var (
	lookPath = exec.LookPath
	run      = func(ctx context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, toolTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- fixed clipboard tools
		cmd.Stdin = stdin
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &out, n: maxReadBytes}
		cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
		if err := cmd.Run(); err != nil {
			// The tool's own message says why (e.g. no data-control).
			return out.Bytes(), fmt.Errorf("%s: %w: %s", argv[0], err, bytes.TrimSpace(stderr.Bytes()))
		}
		return out.Bytes(), nil
	}
)

type linuxChannel struct{}

// New returns the clipboard channel for this platform.
func New() channel.Channel { return linuxChannel{} }

func (linuxChannel) Name() string { return Name }

func (linuxChannel) Supported() channel.Capability {
	_, c := pickBackend(context.Background())
	return c
}

// pickBackend chooses the clipboard backend for this session, or says why
// there is none in the terms an admin can act on.
func pickBackend(ctx context.Context) (backend, channel.Capability) {
	isWayland, isX := os.Getenv("WAYLAND_DISPLAY") != "", os.Getenv("DISPLAY") != ""
	connected := false
	if isX {
		var fixes bool
		if connected, fixes = x11Probe(); fixes {
			return x11Native, channel.Supported()
		}
	}
	dataControl := isWayland && hasWlrDataControl(ctx)
	if dataControl {
		if _, err := lookPath("wl-paste"); err == nil {
			return wayland, channel.Supported()
		}
	}
	if connected {
		if _, err := lookPath("xclip"); err == nil {
			return xclip, channel.Supported()
		}
		if _, err := lookPath("xsel"); err == nil {
			return xsel, channel.Supported()
		}
	}
	switch {
	case dataControl:
		return backend{}, channel.Unsupported("no_wl_clipboard")
	case isX && !connected:
		return backend{}, channel.Unsupported("x11_unavailable")
	case isX:
		return backend{}, channel.Unsupported("no_xclip_or_xsel") // X server without XFixes
	case isWayland:
		return backend{}, channel.Unsupported("wayland_no_data_control")
	default:
		return backend{}, channel.Unsupported("no_graphical_session")
	}
}

// Run watches the clipboard until ctx ends.
func (linuxChannel) Run(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	b, c := pickBackend(ctx)
	if !c.Supported {
		return channel.ErrUnsupported
	}
	if b.native {
		return runX11(ctx, p, sink)
	}
	log.Printf("DLP helper: clipboard via %s (%s)", b.name, b.read[0])
	w := &poller{b: b, p: p, sink: sink}
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			w.check(ctx)
		}
	}
}

type poller struct {
	b    backend
	p    *policy.Compiled
	sink channel.EventSink

	lastHash  [32]byte
	lastBlock bool
	lastSrc   events.SourceApp
	ownHash   [32]byte // our placeholder
}

// check reads the clipboard once and acts on a new copy.
func (w *poller) check(ctx context.Context) {
	out, err := run(ctx, nil, w.b.read...)
	if err != nil || len(out) == 0 {
		return // empty, non-text or briefly unavailable
	}
	hash := sha256.Sum256(out)
	if hash == w.ownHash {
		return // our placeholder
	}
	if hash == w.lastHash && !w.lastBlock {
		// Same text as last time: only new if another app copied it (the
		// source is looked up just for repeats, to keep polling cheap).
		if src := sourceApp(ctx); src == w.lastSrc {
			return
		}
	}
	if w.p.Modules.Clipboard.IgnoreConcealed && w.concealed(ctx) {
		w.lastHash, w.lastBlock, w.lastSrc = hash, false, events.SourceApp{}
		return
	}
	src := sourceApp(ctx)
	d := enforce(w.p, w.sink, out, src, func(msg string) error { return w.replace(ctx, hash, msg) })
	w.lastHash, w.lastBlock, w.lastSrc = hash, d.Block, src
}

// enforce decides on one copy and acts on it: replace puts the placeholder
// on the clipboard when a policy blocks, and a copy it couldn't replace is
// recorded as monitored (the content is still there). A warned copy is left
// alone; the user is told.
func enforce(p *policy.Compiled, sink channel.EventSink, text []byte, src events.SourceApp, replace func(msg string) error) Decision {
	d := Decide(p, string(text), src, time.Now())
	if d.Block {
		if err := replace(d.Message); err != nil {
			log.Printf("DLP helper: clipboard not replaced (%v); recording as monitored", err)
			markMonitored(d.Events)
		}
	}
	notifyUser(d)
	for _, ev := range d.Events {
		sink.Emit(ev)
	}
	return d
}

// replace writes msg in place of the content with hash scanned, unless a
// newer copy has arrived meanwhile (it gets its own check).
func (w *poller) replace(ctx context.Context, scanned [32]byte, msg string) error {
	now, err := run(ctx, nil, w.b.read...)
	if err != nil {
		return fmt.Errorf("re-read before replacing: %w", err) // can't tell what's there now
	}
	if sha256.Sum256(now) != scanned {
		return errors.New("a newer copy replaced the scanned content")
	}
	if _, err := run(ctx, strings.NewReader(msg), w.b.write...); err != nil {
		return err
	}
	w.ownHash = sha256.Sum256([]byte(msg))
	return nil
}

// concealed reports whether a password manager marked the copy.
func (w *poller) concealed(ctx context.Context) bool {
	if len(w.b.targets) == 0 {
		return false
	}
	out, err := run(ctx, nil, w.b.targets...)
	return err == nil && bytes.Contains(out, []byte(hintTarget))
}

// sourceApp names the focused window's app when xdotool is available
// (X11 only; best effort).
func sourceApp(ctx context.Context) events.SourceApp {
	if os.Getenv("DISPLAY") == "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return events.SourceApp{}
	}
	if _, err := lookPath("xdotool"); err != nil {
		return events.SourceApp{}
	}
	out, err := run(ctx, nil, "xdotool", "getactivewindow", "getwindowpid")
	if err != nil {
		return events.SourceApp{}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return events.SourceApp{}
	}
	return processApp(pid)
}

// limitedWriter keeps at most n bytes and drops the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	keep := p
	if len(keep) > l.n {
		keep = keep[:l.n]
	}
	n, err := l.w.Write(keep)
	l.n -= n
	if err != nil {
		return n, err
	}
	return len(p), nil
}
