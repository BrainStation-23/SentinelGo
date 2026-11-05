package scanworker

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// conn is one end of the service<->worker socket pair: frames (protocol.go)
// with a descriptor riding on the length bytes of the frame it belongs to.
type conn struct{ c *net.UnixConn }

// writeMsg sends m, with fd attached when it is >= 0.
func (c conn) writeMsg(m message, fd int) error {
	frame, err := encodeFrame(m)
	if err != nil {
		return err
	}
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
	hdr := make([]byte, 4)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := c.c.ReadMsgUnix(hdr, oob)
	if err != nil {
		return message{}, nil, err
	}
	if n == 0 {
		return message{}, nil, io.EOF
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
	m, err := decodeFrame(c.c, hdr, limit)
	if err != nil {
		return fail(err)
	}
	return m, f, nil
}

func (c conn) setReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

func (c conn) close() error { return c.c.Close() }

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
