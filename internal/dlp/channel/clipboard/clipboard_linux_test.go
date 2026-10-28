package clipboard

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/dlp/events"
)

// fakeDesktop is a clipboard behind the tool seams.
type fakeDesktop struct {
	mu         sync.Mutex
	text       string
	targets    string
	tools      map[string]bool
	waylandErr string
}

func installFake(t *testing.T, d *fakeDesktop) {
	t.Helper()
	prevLook, prevRun := lookPath, run
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
		case argv[0] == "wl-paste" && d.waylandErr != "":
			return []byte(d.waylandErr), errors.New("exit 1")
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
	t.Cleanup(func() { lookPath, run = prevLook, prevRun })
}

func (d *fakeDesktop) copy(text, targets string) {
	d.mu.Lock()
	d.text, d.targets = text, targets
	d.mu.Unlock()
}

func (d *fakeDesktop) clip() string { d.mu.Lock(); defer d.mu.Unlock(); return d.text }

func TestPickBackend(t *testing.T) {
	tests := []struct {
		name, wayland, display string
		tools                  map[string]bool
		waylandErr             string
		want                   string
	}{
		{"headless", "", "", nil, "", "unsupported:no_graphical_session"},
		{"x11 xclip", "", ":0", map[string]bool{"xclip": true}, "", "supported"},
		{"x11 xsel", "", ":0", map[string]bool{"xsel": true}, "", "supported"},
		{"x11 no tool", "", ":0", map[string]bool{}, "", "unsupported:no_xclip_or_xsel"},
		{"wayland ok", "wayland-0", "", map[string]bool{"wl-paste": true}, "", "supported"},
		{"wayland gnome", "wayland-0", "", map[string]bool{"wl-paste": true}, "Compositor does not support the data-control protocol", "unsupported:wayland_no_data_control"},
		{"wayland no tool", "wayland-0", ":0", map[string]bool{"xclip": true}, "", "unsupported:no_wl_clipboard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WAYLAND_DISPLAY", tt.wayland)
			t.Setenv("DISPLAY", tt.display)
			installFake(t, &fakeDesktop{tools: tt.tools, waylandErr: tt.waylandErr})
			if got := New().Supported().String(); got != tt.want {
				t.Errorf("capability = %s, want %s", got, tt.want)
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
