package clipboard

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
)

// fakeDesktop is a clipboard behind the tool seams.
type fakeDesktop struct {
	mu      sync.Mutex
	text    string
	targets string
	tools   map[string]bool
	readErr bool

	xConnected, xFixes bool // what the X server probe finds
	dataControl        bool // the compositor offers zwlr_data_control
}

func installFake(t *testing.T, d *fakeDesktop) {
	t.Helper()
	prevLook, prevRun, prevProbe, prevGlobals := lookPath, run, x11Probe, wlGlobals
	x11Probe = func() (bool, bool) { return d.xConnected, d.xFixes }
	wlGlobals = func(context.Context) (map[string]uint32, error) {
		g := map[string]uint32{"wl_data_device_manager": 3}
		if d.dataControl {
			g[wlrDataControl] = 2
		}
		return g, nil
	}
	lookPath = func(name string) (string, error) {
		if d.tools[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	run = func(_ context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		cmd := strings.Join(argv, " ")
		switch {
		case d.readErr && !strings.Contains(cmd, "TARGETS") && argv[0] != "wl-copy" && !strings.Contains(cmd, " -i"):
			return nil, errors.New("xclip: read failed")
		case strings.Contains(cmd, "TARGETS") || strings.Contains(cmd, "--list-types"):
			return []byte(d.targets), nil
		case argv[0] == "wl-copy" || strings.Contains(cmd, " -i") || strings.Contains(cmd, "--input"):
			b, _ := io.ReadAll(stdin)
			d.text, d.targets = string(b), "UTF8_STRING\n"
			return nil, nil
		default:
			return []byte(d.text), nil
		}
	}
	t.Cleanup(func() { lookPath, run, x11Probe, wlGlobals = prevLook, prevRun, prevProbe, prevGlobals })
}

func (d *fakeDesktop) copy(text, targets string) {
	d.mu.Lock()
	d.text, d.targets = text, targets
	d.mu.Unlock()
}

func (d *fakeDesktop) clip() string { d.mu.Lock(); defer d.mu.Unlock(); return d.text }

func TestPickBackend(t *testing.T) {
	all := map[string]bool{"wl-paste": true, "xclip": true, "xsel": true}
	tests := []struct {
		name, wayland, display string
		d                      *fakeDesktop
		want, backend          string
	}{
		{"headless", "", "", &fakeDesktop{tools: all}, "unsupported:no_graphical_session", ""},
		{"x11 native", "", ":0", &fakeDesktop{xConnected: true, xFixes: true}, "supported", "x11-native"},
		{"x11 no xfixes xclip", "", ":0", &fakeDesktop{xConnected: true, tools: map[string]bool{"xclip": true}}, "supported", "x11"},
		{"x11 no xfixes xsel", "", ":0", &fakeDesktop{xConnected: true, tools: map[string]bool{"xsel": true}}, "supported", "x11"},
		{"x11 no xfixes no tool", "", ":0", &fakeDesktop{xConnected: true}, "unsupported:no_xclip_or_xsel", ""},
		{"x11 server unreachable", "", ":0", &fakeDesktop{tools: all}, "unsupported:x11_unavailable", ""},
		// GNOME: no data-control, XWayland. wl-paste must not be chosen even
		// when installed (it would grab focus on every read).
		{"gnome xwayland", "wayland-0", ":0", &fakeDesktop{xConnected: true, xFixes: true, tools: all}, "supported", "x11-native"},
		{"gnome xwayland no xfixes", "wayland-0", ":0", &fakeDesktop{xConnected: true, tools: all}, "supported", "x11"},
		{"gnome no xwayland", "wayland-0", "", &fakeDesktop{tools: all}, "unsupported:wayland_no_data_control", ""},
		{"gnome xwayland down", "wayland-0", ":0", &fakeDesktop{tools: all}, "unsupported:x11_unavailable", ""},
		// wlroots / KDE: data-control. XWayland still comes first: no tools.
		{"kde xwayland", "wayland-0", ":0", &fakeDesktop{xConnected: true, xFixes: true, dataControl: true, tools: all}, "supported", "x11-native"},
		{"kde no xwayland", "wayland-0", "", &fakeDesktop{dataControl: true, tools: all}, "supported", "wayland"},
		{"kde no xwayland no tool", "wayland-0", "", &fakeDesktop{dataControl: true}, "unsupported:no_wl_clipboard", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WAYLAND_DISPLAY", tt.wayland)
			t.Setenv("DISPLAY", tt.display)
			installFake(t, tt.d)
			if got := New().Supported().String(); got != tt.want {
				t.Errorf("capability = %s, want %s", got, tt.want)
			}
			if b, _ := pickBackend(context.Background()); b.name != tt.backend {
				t.Errorf("backend = %q, want %q", b.name, tt.backend)
			}
		})
	}
}

type recSink struct{ evs []events.Event }

func (r *recSink) Emit(ev events.Event) { r.evs = append(r.evs, ev) }

func TestPoller_BlockMonitorConcealed(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	d := &fakeDesktop{tools: map[string]bool{"xclip": true}}
	installFake(t, d)
	p := compile(t, blockCards+","+monitorFalcon)
	p.Modules.Clipboard.IgnoreConcealed = true
	s := &recSink{}
	w := &poller{b: xclip, p: p, sink: s}
	ctx := context.Background()

	d.copy("card 4111 1111 1111 1111", "UTF8_STRING\n")
	w.check(ctx)
	if got := d.clip(); got != "Blocked by SentinelOps: credit card" || len(s.evs) != 1 {
		t.Fatalf("clipboard %q, events %d", got, len(s.evs))
	}
	w.check(ctx) // our own placeholder: not rescanned
	if len(s.evs) != 1 {
		t.Errorf("placeholder rescanned: %d events", len(s.evs))
	}

	d.copy("project falcon", "UTF8_STRING\n")
	w.check(ctx)
	w.check(ctx) // same text again: one event
	if len(s.evs) != 2 || s.evs[1].Action != events.ActionMonitored || d.clip() != "project falcon" {
		t.Errorf("monitor: events %+v clipboard %q", s.evs, d.clip())
	}

	d.copy("4111111111111111", "UTF8_STRING\nx-kde-passwordManagerHint\n")
	w.check(ctx)
	if d.clip() != "4111111111111111" || len(s.evs) != 2 {
		t.Errorf("concealed copy acted on: clipboard %q events %d", d.clip(), len(s.evs))
	}

	// The secret copied again (not concealed) is blocked again.
	d.copy("card 4111 1111 1111 1111", "UTF8_STRING\n")
	w.check(ctx)
	d.copy("card 4111 1111 1111 1111", "UTF8_STRING\n")
	w.check(ctx)
	if d.clip() != "Blocked by SentinelOps: credit card" {
		t.Errorf("re-copied secret not blocked: %q", d.clip())
	}
}

// A failed write is recorded as monitored, not blocked.
func TestPoller_FailedReplaceIsMonitored(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	d := &fakeDesktop{tools: map[string]bool{"xclip": true}}
	installFake(t, d)
	prev := run
	run = func(ctx context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
		if strings.Contains(strings.Join(argv, " "), " -i") {
			return nil, errors.New("xclip: cannot own selection")
		}
		return prev(ctx, stdin, argv...)
	}
	s := &recSink{}
	w := &poller{b: xclip, p: compile(t, blockCards), sink: s}
	d.copy("4111111111111111", "UTF8_STRING\n")
	w.check(context.Background())
	if len(s.evs) != 1 || s.evs[0].Action != events.ActionMonitored {
		t.Errorf("events = %+v, want one monitored", s.evs)
	}
}

// When the clipboard can't be re-read before replacing, nothing is written
// (a newer copy might be there) and the event says monitored.
func TestPoller_NoWriteWithoutReread(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	d := &fakeDesktop{tools: map[string]bool{"xclip": true}}
	installFake(t, d)
	s := &recSink{}
	w := &poller{b: xclip, p: compile(t, blockCards), sink: s}
	d.copy("4111111111111111", "UTF8_STRING\n")
	reads := 0
	prev := run
	run = func(ctx context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
		if strings.Contains(strings.Join(argv, " "), "UTF8_STRING") {
			reads++
			if reads > 1 {
				return nil, errors.New("xclip: busy")
			}
		}
		return prev(ctx, stdin, argv...)
	}
	w.check(context.Background())
	if d.clip() != "4111111111111111" || len(s.evs) != 1 || s.evs[0].Action != events.ActionMonitored {
		t.Errorf("clipboard %q events %+v", d.clip(), s.evs)
	}
}

// Run polls until cancelled and blocks a copy made meanwhile.
func TestRun_PollsUntilCancelled(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	d := &fakeDesktop{tools: map[string]bool{"xclip": true}, xConnected: true}
	installFake(t, d)
	s := &recSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New().Run(ctx, compile(t, blockCards), s) }()
	d.copy("4111111111111111", "UTF8_STRING")
	deadline := time.Now().Add(5 * time.Second)
	for d.clip() != "Blocked by SentinelOps: credit card" {
		if time.Now().After(deadline) {
			t.Fatalf("not blocked: %q", d.clip())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v", err)
	}

	t.Setenv("DISPLAY", "")
	if err := New().Run(context.Background(), compile(t, blockCards), s); !errors.Is(err, channel.ErrUnsupported) {
		t.Errorf("headless Run = %v, want ErrUnsupported", err)
	}
}

// The source app comes from xdotool's window pid and /proc.
func TestSourceApp_Xdotool(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	prevLook, prevRun := lookPath, run
	t.Cleanup(func() { lookPath, run = prevLook, prevRun })
	lookPath = func(string) (string, error) { return "/usr/bin/xdotool", nil }
	run = func(context.Context, io.Reader, ...string) ([]byte, error) {
		return []byte(strconv.Itoa(os.Getpid()) + "\n"), nil
	}
	src := sourceApp(context.Background())
	if src.Path == "" || src.Name == "" || !strings.HasSuffix(src.Path, src.Name) {
		t.Errorf("source = %+v, want this process", src)
	}

	run = func(context.Context, io.Reader, ...string) ([]byte, error) { return []byte("not-a-pid"), nil }
	if src := sourceApp(context.Background()); src != (events.SourceApp{}) {
		t.Errorf("bad pid gave %+v", src)
	}
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	if src := sourceApp(context.Background()); src != (events.SourceApp{}) {
		t.Errorf("wayland gave %+v (xdotool is X11 only)", src)
	}
}

// The real command runner returns stdout, and stderr inside the error.
func TestRun_RealCommand(t *testing.T) {
	out, err := run(context.Background(), strings.NewReader("hello"), "cat")
	if err != nil || string(out) != "hello" {
		t.Fatalf("cat = %q, %v", out, err)
	}
	_, err = run(context.Background(), nil, "sh", "-c", "echo tool failed for a reason >&2; exit 1")
	if err == nil || !strings.Contains(err.Error(), "tool failed for a reason") {
		t.Errorf("stderr not in error: %v", err)
	}
}

func TestLimitedWriter(t *testing.T) {
	var b strings.Builder
	w := &limitedWriter{w: &b, n: 5}
	if n, err := w.Write([]byte("hello world")); n != 11 || err != nil {
		t.Errorf("Write = %d, %v (must report the full length)", n, err)
	}
	_, _ = w.Write([]byte("more"))
	if b.String() != "hello" {
		t.Errorf("kept %q, want the first 5 bytes", b.String())
	}
}
