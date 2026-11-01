//go:build linux

package clipboard

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// xConn is a minimal X11 protocol client: just what the clipboard needs
// (atoms, one window, properties, selections and XFixes selection events).
// It speaks the core protocol directly over the X server's socket, so the
// agent needs no X library and no cgo.
//
// One goroutine reads from the server: replies and errors go to the request
// waiting for them (by sequence number), events to an unbounded queue, so a
// burst of events can never stall a caller waiting for a reply.
type xConn struct {
	conn net.Conn

	wmu sync.Mutex // serializes writes and the sequence number
	seq uint16

	pmu     sync.Mutex
	pending map[uint16]chan xResult // requests waiting for a reply or an error
	voids   map[uint16]chan xResult // checked requests without a reply

	emu    sync.Mutex
	queue  []any         // decoded events not yet taken
	signal chan struct{} // has a value while queue may be non-empty

	closed chan struct{}
	once   sync.Once

	root, rootVisual uint32
	idBase, idMask   uint32
	nextID           uint32
	maxRequest       int // bytes

	xfixesOpcode byte
	xfixesEvent  atomic.Uint32 // XFixesSelectionNotify's event code, once known (read by the reader)
}

type xResult struct {
	data []byte
	err  error
}

// xError is an error the X server returned for a request.
type xError struct {
	code  byte
	major byte
	value uint32
}

func (e *xError) Error() string {
	return fmt.Sprintf("X error %d (request %d, value 0x%x)", e.code, e.major, e.value)
}

var errXConnClosed = errors.New("X11 connection closed")

// Events, decoded from the server's 32-byte event packets.
type (
	xSelectionNotify  struct{ time, requestor, selection, target, property uint32 }
	xSelectionRequest struct {
		time, owner, requestor, selection, target, property uint32
	}
	xSelectionClear struct{ time, owner, selection uint32 }
	xPropertyNotify struct {
		window, atom, time uint32
		deleted            bool
	}
	// xOwnerChange is XFixesSelectionNotify: the selection has a new owner.
	xOwnerChange struct{ window, owner, selection, timestamp, selectionTimestamp uint32 }
)

// Core protocol constants used here.
const (
	opCreateWindow       = 1
	opChangeWindowAttrs  = 2
	opInternAtom         = 16
	opChangeProperty     = 18
	opGetProperty        = 20
	opSetSelectionOwner  = 22
	opGetSelectionOwner  = 23
	opConvertSelection   = 24
	opSendEvent          = 25
	opGetInputFocus      = 43
	opQueryExtension     = 98
	xfixesQueryVersion   = 0
	xfixesSelectSelInput = 2

	evPropertyNotify   = 28
	evSelectionClear   = 29
	evSelectionRequest = 30
	evSelectionNotify  = 31

	cwEventMask          = 0x800
	eventMaskPropChange  = 0x400000
	windowClassInputOnly = 2
	propModeReplace      = 0
	atomAtom             = 4
	atomCardinal         = 6
	atomWindow           = 33
	anyPropertyType      = 0
	currentTime          = 0

	xfixesSetSelectionOwnerMask = 1

	xDialTimeout  = 5 * time.Second
	xSetupTimeout = 5 * time.Second
	maxReplyBytes = maxReadBytes + 4096 // the largest property read, plus headers
)

// dialXDisplay connects to display (":0", "unix:1.0", "host:2"), or $DISPLAY
// when empty, authenticating with $XAUTHORITY (else ~/.Xauthority).
func dialXDisplay(display string) (*xConn, error) {
	if display == "" {
		display = os.Getenv("DISPLAY")
	}
	host, number, screen, err := parseDisplay(display)
	if err != nil {
		return nil, err
	}
	conn, err := dialXSocket(host, number)
	if err != nil {
		return nil, err
	}
	name, data := xauthCookie(host, number)
	x := &xConn{
		conn: conn, pending: map[uint16]chan xResult{}, voids: map[uint16]chan xResult{},
		signal: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	_ = conn.SetDeadline(time.Now().Add(xSetupTimeout))
	if err := x.setup(name, data, screen); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	go x.read()
	return x, nil
}

// parseDisplay splits "[host]:number[.screen]".
func parseDisplay(d string) (host, number string, screen int, err error) {
	i := strings.LastIndexByte(d, ':')
	if i < 0 {
		return "", "", 0, fmt.Errorf("bad DISPLAY %q", d)
	}
	host, number = d[:i], d[i+1:]
	if j := strings.IndexByte(number, '.'); j >= 0 {
		if screen, err = strconv.Atoi(number[j+1:]); err != nil {
			return "", "", 0, fmt.Errorf("bad DISPLAY %q", d)
		}
		number = number[:j]
	}
	if n, err := strconv.Atoi(number); err != nil || n < 0 {
		return "", "", 0, fmt.Errorf("bad DISPLAY %q", d)
	}
	return host, number, screen, nil
}

// dialXSocket connects to a local display's socket (the path, else the
// abstract socket a sandbox may still reach) or to a remote one over TCP.
// The display comes from the session's own $DISPLAY, and the helper runs as
// that session's user: it reaches nothing the user couldn't.
func dialXSocket(host, number string) (net.Conn, error) {
	if host == "" || host == "unix" {
		path := "/tmp/.X11-unix/X" + number
		c, err := net.DialTimeout("unix", path, xDialTimeout) // #nosec G704 -- the session's X server, see above
		if err == nil {
			return c, nil
		}
		if c, aerr := net.DialTimeout("unix", "@"+path, xDialTimeout); aerr == nil { // #nosec G704 -- as above
			return c, nil
		}
		return nil, err
	}
	n, _ := strconv.Atoi(number) // checked by parseDisplay
	addr := net.JoinHostPort(strings.TrimPrefix(host, "tcp/"), strconv.Itoa(6000+n))
	return net.DialTimeout("tcp", addr, xDialTimeout) // #nosec G704 -- as above
}

// Xauthority families (Xauth.h).
const (
	familyLocal = 256
	familyWild  = 65535
)

// xauthCookie finds the MIT-MAGIC-COOKIE-1 for a display in the Xauthority
// file. Without one the connection is tried without authorization (Xvfb,
// xhost setups).
func xauthCookie(host, number string) (string, []byte) {
	path := os.Getenv("XAUTHORITY")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", nil
		}
		path = filepath.Join(home, ".Xauthority")
	}
	f, err := os.Open(path) // #nosec G304 G703 -- the session's own Xauthority file, read as its user
	if err != nil {
		return "", nil
	}
	defer func() { _ = f.Close() }()
	local := host == "" || host == "unix"
	hostname, _ := os.Hostname()
	return findCookie(bufio.NewReader(f), local, hostname, number)
}

// findCookie reads Xauthority entries: family, address, number, name and
// data, each a big-endian uint16 length (family: the value) and bytes.
func findCookie(r io.Reader, local bool, hostname, number string) (string, []byte) {
	field := func() ([]byte, error) {
		var n uint16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	for {
		var family uint16
		if err := binary.Read(r, binary.BigEndian, &family); err != nil {
			return "", nil
		}
		addr, err1 := field()
		num, err2 := field()
		name, err3 := field()
		data, err4 := field()
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return "", nil
		}
		hostOK := family == familyWild || (local && family == familyLocal && string(addr) == hostname)
		if hostOK && (len(num) == 0 || string(num) == number) && string(name) == "MIT-MAGIC-COOKIE-1" {
			return string(name), data
		}
	}
}

func pad4(n int) int { return (n + 3) &^ 3 }

// u16 and u32 convert lengths the protocol carries in 16 or 32 bits; the
// callers bound them (requests by maxRequest, names by their use).
func u16(n int) uint16 { return uint16(n) } // #nosec G115 -- bounded by the caller
func u32(n int) uint32 { return uint32(n) } // #nosec G115 -- bounded by the caller

// setup sends the connection setup and reads the server's answer.
func (x *xConn) setup(authName string, authData []byte, screen int) error {
	req := make([]byte, 12+pad4(len(authName))+pad4(len(authData)))
	req[0] = 'l' // little endian
	binary.LittleEndian.PutUint16(req[2:], 11)
	binary.LittleEndian.PutUint16(req[6:], u16(len(authName)))
	binary.LittleEndian.PutUint16(req[8:], u16(len(authData)))
	copy(req[12:], authName)
	copy(req[12+pad4(len(authName)):], authData)
	if _, err := x.conn.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(x.conn, hdr); err != nil {
		return err
	}
	body := make([]byte, 4*int(binary.LittleEndian.Uint16(hdr[6:])))
	if _, err := io.ReadFull(x.conn, body); err != nil {
		return err
	}
	if hdr[0] != 1 {
		reason := body
		if hdr[0] == 0 && int(hdr[1]) <= len(body) {
			reason = body[:hdr[1]]
		}
		return fmt.Errorf("the X server refused the connection: %s", strings.TrimSpace(string(reason)))
	}
	return x.parseSetup(body, screen)
}

// parseSetup reads the resource id range, the maximum request length and
// the screen's root window and visual.
func (x *xConn) parseSetup(b []byte, screen int) error {
	if len(b) < 32 {
		return errors.New("short X setup reply")
	}
	x.idBase = binary.LittleEndian.Uint32(b[4:])
	x.idMask = binary.LittleEndian.Uint32(b[8:])
	vendorLen := int(binary.LittleEndian.Uint16(b[16:]))
	x.maxRequest = 4 * int(binary.LittleEndian.Uint16(b[18:]))
	screens, formats := int(b[20]), int(b[21])
	off := 32 + pad4(vendorLen) + 8*formats
	for i := 0; i < screens; i++ {
		if off+40 > len(b) {
			return errors.New("short X setup reply")
		}
		if i == screen {
			x.root = binary.LittleEndian.Uint32(b[off:])
			x.rootVisual = binary.LittleEndian.Uint32(b[off+32:])
			return nil
		}
		depths := int(b[off+39])
		off += 40
		for d := 0; d < depths; d++ {
			if off+8 > len(b) {
				return errors.New("short X setup reply")
			}
			off += 8 + 24*int(binary.LittleEndian.Uint16(b[off+2:]))
		}
	}
	return fmt.Errorf("no screen %d on the X server", screen)
}

// read dispatches everything the server sends until the connection ends.
func (x *xConn) read() {
	r := bufio.NewReaderSize(x.conn, 64<<10)
	defer x.shutdown() // also on a reply too large to take: the stream can't be resynced
	pkt := make([]byte, 32)
	for {
		if _, err := io.ReadFull(r, pkt); err != nil {
			return
		}
		seq := binary.LittleEndian.Uint16(pkt[2:])
		switch pkt[0] {
		case 0: // error
			x.finish(seq, xResult{err: &xError{code: pkt[1], value: binary.LittleEndian.Uint32(pkt[4:]), major: pkt[10]}}, false)
		case 1: // reply
			extra := binary.LittleEndian.Uint32(pkt[4:])
			if extra > maxReplyBytes/4 {
				return
			}
			data := make([]byte, 32+4*int(extra))
			copy(data, pkt)
			if _, err := io.ReadFull(r, data[32:]); err != nil {
				return
			}
			x.finish(seq, xResult{data: data}, true)
		default:
			if ev := x.decode(pkt); ev != nil {
				x.push(ev)
			}
		}
	}
}

// finish hands a reply or error to its request. A reply also means every
// checked request sent before it succeeded (the server answers in order).
func (x *xConn) finish(seq uint16, res xResult, reply bool) {
	x.pmu.Lock()
	defer x.pmu.Unlock()
	if ch, ok := x.pending[seq]; ok {
		delete(x.pending, seq)
		ch <- res
	} else if ch, ok := x.voids[seq]; ok {
		delete(x.voids, seq)
		ch <- res
	}
	if reply {
		for s, ch := range x.voids {
			if int16(seq-s) > 0 { // #nosec G115 -- sequence numbers wrap; the signed difference orders them
				delete(x.voids, s)
				ch <- xResult{}
			}
		}
	}
}

func (x *xConn) decode(p []byte) any {
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(p[i:]) }
	switch code := p[0] & 0x7f; {
	case code == evPropertyNotify:
		return xPropertyNotify{window: u(4), atom: u(8), time: u(12), deleted: p[16] == 1}
	case code == evSelectionClear:
		return xSelectionClear{time: u(4), owner: u(8), selection: u(12)}
	case code == evSelectionRequest:
		return xSelectionRequest{time: u(4), owner: u(8), requestor: u(12), selection: u(16), target: u(20), property: u(24)}
	case code == evSelectionNotify:
		return xSelectionNotify{time: u(4), requestor: u(8), selection: u(12), target: u(16), property: u(20)}
	case code != 0 && uint32(code) == x.xfixesEvent.Load():
		return xOwnerChange{window: u(4), owner: u(8), selection: u(12), timestamp: u(16), selectionTimestamp: u(20)}
	}
	return nil
}

func (x *xConn) push(ev any) {
	x.emu.Lock()
	x.queue = append(x.queue, ev)
	x.emu.Unlock()
	select {
	case x.signal <- struct{}{}:
	default:
	}
}

// nextEvent returns the next event, waiting until one arrives, deadline
// passes (zero: no deadline) or done closes.
func (x *xConn) nextEvent(done <-chan struct{}, deadline time.Time) (any, error) {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	for {
		x.emu.Lock()
		if len(x.queue) > 0 {
			ev := x.queue[0]
			x.queue = x.queue[1:]
			x.emu.Unlock()
			return ev, nil
		}
		x.emu.Unlock()
		select {
		case <-x.signal:
		case <-x.closed:
			x.emu.Lock()
			empty := len(x.queue) == 0
			x.emu.Unlock()
			if empty {
				return nil, errXConnClosed
			}
		case <-timeout:
			return nil, errXTimeout
		case <-done:
			return nil, errXCanceled
		}
	}
}

// eventQueued reports whether a queued event satisfies match.
func (x *xConn) eventQueued(match func(any) bool) bool {
	x.emu.Lock()
	defer x.emu.Unlock()
	for _, ev := range x.queue {
		if match(ev) {
			return true
		}
	}
	return false
}

// shutdown ends the connection; requests still waiting get errXConnClosed.
func (x *xConn) shutdown() {
	x.once.Do(func() {
		close(x.closed)
		_ = x.conn.Close()
		x.pmu.Lock()
		for s, ch := range x.pending {
			delete(x.pending, s)
			ch <- xResult{err: errXConnClosed}
		}
		for s, ch := range x.voids {
			delete(x.voids, s)
			ch <- xResult{err: errXConnClosed}
		}
		x.pmu.Unlock()
	})
}

func (x *xConn) close() { x.shutdown() }

// request is a request under construction: opcode, data byte, body.
type request struct{ b []byte }

func newRequest(opcode, data byte) *request { return &request{b: []byte{opcode, data, 0, 0}} }

func (r *request) u8(v byte) *request    { r.b = append(r.b, v); return r }
func (r *request) u16(v uint16) *request { r.b = binary.LittleEndian.AppendUint16(r.b, v); return r }
func (r *request) u32(v uint32) *request { r.b = binary.LittleEndian.AppendUint32(r.b, v); return r }
func (r *request) bytes(v []byte) *request {
	r.b = append(r.b, v...)
	for len(r.b)%4 != 0 {
		r.b = append(r.b, 0)
	}
	return r
}

// send writes r and returns its sequence number; with wait set, the reply
// or error is delivered on the returned channel (voids: checked requests
// without a reply, completed by a later reply).
func (x *xConn) send(r *request, wait, void bool) (chan xResult, error) {
	if len(r.b) > x.maxRequest {
		return nil, fmt.Errorf("request of %d bytes exceeds the X server's limit of %d", len(r.b), x.maxRequest)
	}
	binary.LittleEndian.PutUint16(r.b[2:], u16(len(r.b)/4))
	x.wmu.Lock()
	defer x.wmu.Unlock()
	select {
	case <-x.closed:
		return nil, errXConnClosed
	default:
	}
	x.seq++
	var ch chan xResult
	if wait {
		ch = make(chan xResult, 1)
		x.pmu.Lock()
		if void {
			x.voids[x.seq] = ch
		} else {
			x.pending[x.seq] = ch
		}
		x.pmu.Unlock()
	}
	if _, err := x.conn.Write(r.b); err != nil {
		go x.shutdown()
		return nil, errXConnClosed
	}
	return ch, nil
}

// call sends a request with a reply and waits for it.
func (x *xConn) call(r *request) ([]byte, error) {
	ch, err := x.send(r, true, false)
	if err != nil {
		return nil, err
	}
	res := <-ch
	return res.data, res.err
}

// checked sends a request without a reply and reports its error, if any,
// by following it with a round trip.
func (x *xConn) checked(r *request) error {
	ch, err := x.send(r, true, true)
	if err != nil {
		return err
	}
	if _, err := x.call(newRequest(opGetInputFocus, 0)); err != nil {
		return err
	}
	return (<-ch).err
}

// do sends a request without a reply and doesn't wait.
func (x *xConn) do(r *request) error {
	_, err := x.send(r, false, false)
	return err
}

func (x *xConn) newID() uint32 {
	x.wmu.Lock()
	defer x.wmu.Unlock()
	x.nextID++
	return x.idBase | (x.nextID & x.idMask)
}

func (x *xConn) internAtom(name string) (uint32, error) {
	rep, err := x.call(newRequest(opInternAtom, 0).u16(u16(len(name))).u16(0).bytes([]byte(name)))
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(rep[8:]), nil
}

// createInputWindow creates an unmapped InputOnly window with eventMask.
func (x *xConn) createInputWindow(eventMask uint32) (uint32, error) {
	w := x.newID()
	r := newRequest(opCreateWindow, 0).u32(w).u32(x.root).
		u16(0).u16(0).u16(1).u16(1).u16(0). // x, y, width, height, border
		u16(windowClassInputOnly).u32(0)    // class, visual: CopyFromParent
	if eventMask != 0 {
		r.u32(cwEventMask).u32(eventMask)
	} else {
		r.u32(0)
	}
	return w, x.checked(r)
}

func (x *xConn) selectWindowEvents(w, eventMask uint32) error {
	return x.do(newRequest(opChangeWindowAttrs, 0).u32(w).u32(cwEventMask).u32(eventMask))
}

// initXFixes finds the XFixes extension and negotiates version 2 or later
// (selection events need 2).
func (x *xConn) initXFixes() error {
	name := "XFIXES"
	rep, err := x.call(newRequest(opQueryExtension, 0).u16(u16(len(name))).u16(0).bytes([]byte(name)))
	if err != nil {
		return err
	}
	if rep[8] == 0 {
		return errors.New("no XFixes on the X server")
	}
	op, ev := rep[9], rep[10]
	rep, err = x.call(newRequest(op, xfixesQueryVersion).u32(5).u32(0))
	if err != nil {
		return err
	}
	if v := binary.LittleEndian.Uint32(rep[8:]); v < 2 {
		return fmt.Errorf("XFixes %d is too old", v)
	}
	x.xfixesOpcode = op
	x.xfixesEvent.Store(uint32(ev))
	return nil
}

// watchSelectionOwner asks for an xOwnerChange each time sel gets an owner.
func (x *xConn) watchSelectionOwner(w, sel uint32) error {
	return x.checked(newRequest(x.xfixesOpcode, xfixesSelectSelInput).u32(w).u32(sel).u32(xfixesSetSelectionOwnerMask))
}

func (x *xConn) convertSelection(requestor, sel, target, prop, t uint32) error {
	return x.do(newRequest(opConvertSelection, 0).u32(requestor).u32(sel).u32(target).u32(prop).u32(t))
}

// xProperty is a property's value: its type, format (8, 16 or 32) and
// bytes; more says how many bytes past maxBytes weren't read.
type xProperty struct {
	typ    uint32
	format byte
	value  []byte
	more   uint32
}

// getProperty reads up to maxBytes of a property, deleting it when asked
// (and when it was read whole).
func (x *xConn) getProperty(del bool, w, prop, typ uint32, maxBytes int) (xProperty, error) {
	d := byte(0)
	if del {
		d = 1
	}
	rep, err := x.call(newRequest(opGetProperty, d).u32(w).u32(prop).u32(typ).u32(0).u32(u32(pad4(maxBytes) / 4)))
	if err != nil {
		return xProperty{}, err
	}
	p := xProperty{format: rep[1], typ: binary.LittleEndian.Uint32(rep[8:]), more: binary.LittleEndian.Uint32(rep[12:])}
	n := int(binary.LittleEndian.Uint32(rep[16:])) * int(p.format) / 8
	if 32+n > len(rep) {
		return xProperty{}, errors.New("short X property reply")
	}
	p.value = rep[32 : 32+n]
	return p, nil
}

func (x *xConn) changeProperty(w, prop, typ uint32, format byte, data []byte) error {
	return x.do(newRequest(opChangeProperty, propModeReplace).u32(w).u32(prop).u32(typ).
		u8(format).u8(0).u16(0).u32(u32(len(data) / int(format/8))).bytes(data))
}

func (x *xConn) setSelectionOwner(owner, sel, t uint32) error {
	return x.do(newRequest(opSetSelectionOwner, 0).u32(owner).u32(sel).u32(t))
}

func (x *xConn) selectionOwner(sel uint32) (uint32, error) {
	rep, err := x.call(newRequest(opGetSelectionOwner, 0).u32(sel))
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(rep[8:]), nil
}

// sendSelectionNotify tells a requestor its conversion is done (property
// 0: refused).
func (x *xConn) sendSelectionNotify(e xSelectionRequest, property uint32) error {
	ev := make([]byte, 32)
	ev[0] = evSelectionNotify
	binary.LittleEndian.PutUint32(ev[4:], e.time)
	binary.LittleEndian.PutUint32(ev[8:], e.requestor)
	binary.LittleEndian.PutUint32(ev[12:], e.selection)
	binary.LittleEndian.PutUint32(ev[16:], e.target)
	binary.LittleEndian.PutUint32(ev[20:], property)
	return x.do(newRequest(opSendEvent, 0).u32(e.requestor).u32(0).bytes(ev))
}
