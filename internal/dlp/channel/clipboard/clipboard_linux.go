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

// On Linux the clipboard is read and written with the desktop's own tools,
// as subprocesses (no cgo, no X11/Wayland client library):
//
//   - Wayland: wl-paste / wl-copy (wl-clipboard). Background access needs the
//     compositor's data-control protocol (wlroots, KDE); without it (GNOME)
//     the channel reports unsupported:wayland_no_data_control, never a
//     silent no-op.
//   - X11: xclip, else xsel.
//
// The clipboard is polled every pollInterval (these tools have no change
// notification for X11, so new copies are found by comparing the text's
// hash). A copy marked by a password manager (x-kde-passwordManagerHint, set
// by KeePassXC and KDE apps) is ignored when the policy says so.
const (
	pollInterval = 400 * time.Millisecond
	toolTimeout  = 2 * time.Second
	maxReadBytes = 16 << 20
	hintTarget   = "x-kde-passwordManagerHint"
)

// backend is one way to reach the session's clipboard.
type backend struct {
	name    string
	read    []string // prints the clipboard text
	targets []string // prints the offered MIME types/targets, one per line
	write   []string // reads the new text on stdin and owns the clipboard
}

var (
	wayland = backend{
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

// pickBackend chooses the clipboard tool for this session.
func pickBackend(ctx context.Context) (backend, channel.Capability) {
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "":
		if _, err := lookPath("wl-paste"); err != nil {
			return backend{}, channel.Unsupported("no_wl_clipboard")
		}
		// wl-paste fails at once when the compositor lacks data-control.
		if _, err := run(ctx, nil, wayland.targets...); err != nil && dataControlMissing([]byte(err.Error())) {
			return backend{}, channel.Unsupported("wayland_no_data_control")
		}
		return wayland, channel.Supported()
	case os.Getenv("DISPLAY") != "":
		if _, err := lookPath("xclip"); err == nil {
			return xclip, channel.Supported()
		}
		if _, err := lookPath("xsel"); err == nil {
			return xsel, channel.Supported()
		}
		return backend{}, channel.Unsupported("no_xclip_or_xsel")
	default:
		return backend{}, channel.Unsupported("no_graphical_session")
	}
}

func dataControlMissing(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "data-control") || strings.Contains(s, "data control") || strings.Contains(s, "not supported")
}

// Run polls the clipboard until ctx ends.
func (linuxChannel) Run(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	b, c := pickBackend(ctx)
	if !c.Supported {
		return channel.ErrUnsupported
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
	d := Decide(w.p, string(out), src, time.Now())
	w.lastHash, w.lastBlock, w.lastSrc = hash, d.Block, src
	if d.Block {
		if err := w.replace(ctx, hash, d.Message); err != nil {
			// The content is still there: don't claim it was blocked.
			log.Printf("DLP helper: clipboard not replaced (%v); recording as monitored", err)
			markMonitored(d.Events)
		}
	}
	for _, ev := range d.Events {
		w.sink.Emit(ev)
	}
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
	if err != nil || pid <= 0 {
		return events.SourceApp{}
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return events.SourceApp{}
	}
	return events.SourceApp{Name: exe[strings.LastIndexByte(exe, '/')+1:], Path: exe}
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
