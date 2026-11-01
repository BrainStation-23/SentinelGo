package clipboard

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// wlEvent encodes a compositor event.
func wlEvent(obj uint32, opcode uint16, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint32(b[0:], obj)
	binary.LittleEndian.PutUint32(b[4:], uint32(8+len(body))<<16|uint32(opcode))
	return append(b, body...)
}

// wlGlobal encodes wl_registry.global.
func wlGlobal(name uint32, iface string, version uint32) []byte {
	n := len(iface) + 1
	body := make([]byte, 8+(n+3)&^3+4)
	binary.LittleEndian.PutUint32(body[0:], name)
	binary.LittleEndian.PutUint32(body[4:], uint32(n))
	copy(body[8:], iface)
	binary.LittleEndian.PutUint32(body[8+(n+3)&^3:], version)
	return wlEvent(wlRegistry, 0, body)
}

var wlDone = wlEvent(wlCallback, 0, []byte{0, 0, 0, 0})

// fakeCompositor serves one client: it checks the probe's requests, then
// writes reply (and stalls after it when stall is set).
func fakeCompositor(t *testing.T, reply []byte, stall bool) {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "wayland-test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("WAYLAND_DISPLAY", "wayland-test")
	done := make(chan struct{})
	t.Cleanup(func() { _ = l.Close(); <-done })
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		req := make([]byte, 24)
		if _, err := io.ReadFull(c, req); err != nil {
			t.Errorf("read requests: %v", err)
			return
		}
		want := append(wlMessage(wlDisplay, 1, wlRegistry), wlMessage(wlDisplay, 0, wlCallback)...)
		if !bytes.Equal(req, want) {
			t.Errorf("requests = %x, want get_registry + sync %x", req, want)
		}
		_, _ = c.Write(reply)
		if stall {
			_, _ = io.Copy(io.Discard, c) // until the client gives up
		}
	}()
}

func TestWaylandGlobals(t *testing.T) {
	reply := bytes.Join([][]byte{
		wlGlobal(1, "wl_compositor", 6),
		wlGlobal(2, "wl_data_device_manager", 3),
		wlGlobal(3, wlrDataControl, 2),
		wlGlobal(4, "ext_data_control_manager_v1", 1),
		wlEvent(wlDisplay, 1, []byte{3, 0, 0, 0}), // delete_id: ignored
		wlDone,
		wlGlobal(5, "after_done", 1), // never read
	}, nil)
	fakeCompositor(t, reply, false)
	g, err := waylandGlobals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g[wlrDataControl] != 2 || g["wl_compositor"] != 6 || g["ext_data_control_manager_v1"] != 1 || len(g) != 4 {
		t.Errorf("globals = %v", g)
	}
}

// GNOME: no data-control, so wl-clipboard is never used.
func TestHasWlrDataControl(t *testing.T) {
	fakeCompositor(t, append(wlGlobal(1, "wl_data_device_manager", 3), wlDone...), false)
	if hasWlrDataControl(context.Background()) {
		t.Error("data-control reported without the global")
	}
	fakeCompositor(t, append(wlGlobal(1, wlrDataControl, 2), wlDone...), false)
	if !hasWlrDataControl(context.Background()) {
		t.Error("data-control global not found")
	}
	// ext-data-control alone isn't enough: wl-clipboard only speaks zwlr.
	fakeCompositor(t, append(wlGlobal(1, "ext_data_control_manager_v1", 1), wlDone...), false)
	if hasWlrDataControl(context.Background()) {
		t.Error("ext_data_control taken as zwlr_data_control")
	}
}

func TestWaylandGlobals_Failures(t *testing.T) {
	big := make([]byte, 8)
	binary.LittleEndian.PutUint32(big[0:], wlRegistry)
	binary.LittleEndian.PutUint32(big[4:], uint32(wlMaxMessage+4)<<16)
	tests := []struct {
		name  string
		reply []byte
		stall bool
	}{
		{"protocol error", wlEvent(wlDisplay, 0, make([]byte, 12)), false},
		{"oversized message", big, false},
		{"unaligned size", []byte{2, 0, 0, 0, 0, 0, 9, 0}, false},
		{"connection closed", wlGlobal(1, "wl_compositor", 6), false},
		{"no reply", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeCompositor(t, tt.reply, tt.stall)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			if g, err := waylandGlobals(ctx); err == nil {
				t.Errorf("globals = %v, want an error", g)
			}
			if time.Since(start) > 2*time.Second {
				t.Errorf("took %v", time.Since(start))
			}
		})
	}
}

func TestWaylandGlobals_Environment(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	if _, err := waylandGlobals(context.Background()); err == nil {
		t.Error("no WAYLAND_DISPLAY: want an error")
	}
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("XDG_RUNTIME_DIR", "")
	if _, err := waylandGlobals(context.Background()); err == nil {
		t.Error("relative display without XDG_RUNTIME_DIR: want an error")
	}
	t.Setenv("WAYLAND_DISPLAY", filepath.Join(t.TempDir(), "missing"))
	if _, err := waylandGlobals(context.Background()); err == nil {
		t.Error("missing socket: want an error")
	}

	// An absolute WAYLAND_DISPLAY is used as is.
	fakeCompositor(t, append(wlGlobal(1, wlrDataControl, 2), wlDone...), false)
	t.Setenv("WAYLAND_DISPLAY", filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "wayland-test"))
	t.Setenv("XDG_RUNTIME_DIR", "")
	if g, err := waylandGlobals(context.Background()); err != nil || len(g) != 1 {
		t.Errorf("absolute path: %v, %v", g, err)
	}
}
