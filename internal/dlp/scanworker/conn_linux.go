package scanworker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/filescan"
)

// Message types.
const (
	typeReady  = "ready"  // worker -> service, once sandboxed
	typePolicy = "policy" // service -> worker: the bundle to scan with
	typeScan   = "scan"   // service -> worker, with the file's descriptor
	typeResult = "result" // worker -> service
)

// message is one frame of the protocol.
type message struct {
	Type    string           `json:"type"`
	ID      uint64           `json:"id,omitempty"`
	Bundle  json.RawMessage  `json:"bundle,omitempty"`  // policy
	Size    int64            `json:"size,omitempty"`    // scan
	Result  *filescan.Result `json:"result,omitempty"`  // result
	Sandbox string           `json:"sandbox,omitempty"` // ready: what the sandbox applies
	Error   string           `json:"error,omitempty"`
}

// Frame limits: a bundle is at most 8 MB; results are capped below.
const (
	maxFrameToWorker   = 9 << 20
	maxFrameFromWorker = 8 << 20
	// maxOffsets caps match offsets per finding in a result (the count is
	// kept), so a file full of e-mail addresses can't make a huge reply.
	maxOffsets = 10000
)

// capOffsets trims each finding's offsets to maxOffsets.
func capOffsets(r *filescan.Result) {
	for i := range r.Findings {
		if len(r.Findings[i].Offsets) > maxOffsets {
			r.Findings[i].Offsets = r.Findings[i].Offsets[:maxOffsets]
		}
	}
	for e := range r.Entries {
		for i := range r.Entries[e].Findings {
			if len(r.Entries[e].Findings[i].Offsets) > maxOffsets {
				r.Entries[e].Findings[i].Offsets = r.Entries[e].Findings[i].Offsets[:maxOffsets]
			}
		}
	}
}

// conn is one end of the service<->worker socket pair: frames are a 4-byte
// big-endian length and a JSON message; a descriptor rides on the length
// bytes of the frame it belongs to.
type conn struct{ c *net.UnixConn }

// writeMsg sends m, with fd attached when it is >= 0.
func (c conn) writeMsg(m message, fd int) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	frame := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body))) // #nosec G115 -- frames are capped far below 4 GB
	frame = append(frame, body...)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	n, oobn, err := c.c.WriteMsgUnix(frame, oob, nil)
	if err != nil {
		return err
	}
	if oobn != len(oob) {
		return errors.New("scanworker: descriptor not sent")
	}
	if n < len(frame) {
		_, err = c.c.Write(frame[n:])
	}
	return err
}

// readMsg reads one frame of at most limit bytes, and the descriptor that
// came with it (nil if none). Extra descriptors are closed.
func (c conn) readMsg(limit int) (message, *os.File, error) {
	var m message
	hdr := make([]byte, 4)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := c.c.ReadMsgUnix(hdr, oob)
	if err != nil {
		return m, nil, err
	}
	if n == 0 {
		return m, nil, io.EOF
	}
	f, ferr := takeFD(oob[:oobn])
	fail := func(err error) (message, *os.File, error) {
		if f != nil {
			_ = f.Close()
		}
		return message{}, nil, err
	}
	if ferr != nil {
		return fail(ferr)
	}
	if n < 4 {
		if _, err := io.ReadFull(c.c, hdr[n:]); err != nil {
			return fail(err)
		}
	}
	size := binary.BigEndian.Uint32(hdr)
	if size > uint32(limit) { // #nosec G115 -- limit is a small positive constant
		return fail(fmt.Errorf("scanworker: frame of %d bytes over the %d-byte limit", size, limit))
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c.c, body); err != nil {
		return fail(err)
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return fail(fmt.Errorf("scanworker: bad frame: %w", err))
	}
	return m, f, nil
}

// takeFD returns the first descriptor in a control message and closes any
// others.
func takeFD(oob []byte) (*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, cm := range cmsgs {
		if got, err := unix.ParseUnixRights(&cm); err == nil {
			fds = append(fds, got...)
		}
	}
	if len(fds) == 0 {
		return nil, nil
	}
	for _, extra := range fds[1:] {
		_ = unix.Close(extra)
	}
	unix.CloseOnExec(fds[0])
	return os.NewFile(uintptr(fds[0]), "scan-input"), nil // #nosec G115 -- a descriptor from the kernel
}

// socketPair returns the service's end (as a conn) and the worker's end (as
// a file to hand over as fd 3).
func socketPair() (conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return conn{}, nil, err
	}
	parent := os.NewFile(uintptr(fds[0]), "scan-worker")      // #nosec G115 -- descriptors from the kernel
	child := os.NewFile(uintptr(fds[1]), "scan-worker-child") // #nosec G115 -- descriptors from the kernel
	fc, err := net.FileConn(parent)
	_ = parent.Close() // FileConn dups it
	if err != nil {
		_ = child.Close()
		return conn{}, nil, err
	}
	uc, ok := fc.(*net.UnixConn)
	if !ok {
		_ = fc.Close()
		_ = child.Close()
		return conn{}, nil, errors.New("scanworker: socket pair is not a unix socket")
	}
	return conn{uc}, child, nil
}

// fileConn wraps a socket descriptor as a conn; f is closed (the conn holds
// its own copy).
func fileConn(f *os.File) (conn, *net.UnixConn, error) {
	fc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return conn{}, nil, err
	}
	uc, ok := fc.(*net.UnixConn)
	if !ok {
		_ = fc.Close()
		return conn{}, nil, errors.New("scanworker: not a unix socket")
	}
	return conn{uc}, uc, nil
}
