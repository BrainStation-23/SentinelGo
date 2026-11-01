//go:build linux

package clipboard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The Wayland registry lists the protocols the compositor offers. wl-paste
// and wl-copy read the clipboard from the background only through
// zwlr_data_control_manager_v1; without it (GNOME) they open a window and ask
// for focus on every call, so the channel never runs them there. The probe
// is read-only: it asks for the registry and a sync, and creates no surface.
const (
	wlProbeTimeout = time.Second
	wlMaxMessage   = 4096
	wlrDataControl = "zwlr_data_control_manager_v1"
)

// Object ids and opcodes the probe uses (wayland.xml).
const (
	wlDisplay  = 1 // wl_display: requests sync (0), get_registry (1); event error (0)
	wlRegistry = 2 // wl_registry: event global (0)
	wlCallback = 3 // wl_callback: event done (0)
)

// wlGlobals is a seam for tests.
var wlGlobals = waylandGlobals

// hasWlrDataControl reports whether the session's compositor offers the
// data-control protocol wl-clipboard needs. A failed probe counts as no.
func hasWlrDataControl(ctx context.Context) bool {
	g, err := wlGlobals(ctx)
	if err != nil {
		return false
	}
	_, ok := g[wlrDataControl]
	return ok
}

// waylandGlobals returns the compositor's globals (interface name to
// version) from $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY.
func waylandGlobals(ctx context.Context) (map[string]uint32, error) {
	path := os.Getenv("WAYLAND_DISPLAY")
	if path == "" {
		return nil, errors.New("WAYLAND_DISPLAY not set")
	}
	if !filepath.IsAbs(path) {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			return nil, errors.New("XDG_RUNTIME_DIR not set")
		}
		path = filepath.Join(dir, path)
	}
	ctx, cancel := context.WithTimeout(ctx, wlProbeTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	req := append(wlMessage(wlDisplay, 1, wlRegistry), wlMessage(wlDisplay, 0, wlCallback)...)
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	return readGlobals(c)
}

// wlMessage encodes a request whose arguments are all uint32.
func wlMessage(obj uint32, opcode uint16, args ...uint32) []byte {
	b := make([]byte, 8+4*len(args))
	binary.LittleEndian.PutUint32(b[0:], obj)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b))<<16|uint32(opcode))
	for i, a := range args {
		binary.LittleEndian.PutUint32(b[8+4*i:], a)
	}
	return b
}

// readGlobals reads events until the sync's callback is done.
func readGlobals(r io.Reader) (map[string]uint32, error) {
	globals := map[string]uint32{}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, err
		}
		obj := binary.LittleEndian.Uint32(hdr[0:])
		word := binary.LittleEndian.Uint32(hdr[4:])
		size, opcode := int(word>>16), word&0xffff
		if size < 8 || size > wlMaxMessage || size%4 != 0 {
			return nil, fmt.Errorf("wayland: bad message size %d", size)
		}
		body := make([]byte, size-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		switch {
		case obj == wlCallback && opcode == 0:
			return globals, nil
		case obj == wlDisplay && opcode == 0:
			return nil, errors.New("wayland: protocol error")
		case obj == wlRegistry && opcode == 0:
			if name, version, ok := parseGlobal(body); ok {
				globals[name] = version
			}
		}
	}
}

// parseGlobal decodes wl_registry.global: name uint32, interface string
// (length including the NUL, then the bytes padded to 4), version uint32.
func parseGlobal(b []byte) (string, uint32, bool) {
	if len(b) < 8 {
		return "", 0, false
	}
	n := int(binary.LittleEndian.Uint32(b[4:]))
	padded := (n + 3) &^ 3
	if n < 1 || 8+padded+4 > len(b) {
		return "", 0, false
	}
	return string(b[8 : 8+n-1]), binary.LittleEndian.Uint32(b[8+padded:]), true
}
