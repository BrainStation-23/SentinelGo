package scanworker

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// pipeConn is one end of the service <-> worker channel on Windows: two
// anonymous pipes (the worker's stdin and stdout) carrying frames. A file
// arrives as a handle the service duplicated into the worker
// (message.Handle); only the worker side adopts it.
//
// Anonymous pipes have no read deadlines, so a read runs in its own
// goroutine and readMsg gives up at the deadline. The pool then kills the
// worker, which ends that read; a conn whose read timed out is broken.
type pipeConn struct {
	r, w   *os.File
	worker bool // this end adopts handles in messages

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{} // closed (and replaced) when the deadline changes
	broken   bool
}

func newPipeConn(r, w *os.File, worker bool) *pipeConn {
	return &pipeConn{r: r, w: w, worker: worker, changed: make(chan struct{})}
}

var errBrokenConn = errors.New("scanworker: connection broken by an earlier timeout")

func (c *pipeConn) writeMsg(m message, _ int) error {
	frame, err := encodeFrame(m)
	if err != nil {
		return err
	}
	_, err = c.w.Write(frame)
	return err
}

func (c *pipeConn) setReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

type frameResult struct {
	m   message
	err error
}

func (c *pipeConn) readFrame(limit int) frameResult {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c.r, hdr); err != nil {
		return frameResult{err: err}
	}
	m, err := decodeFrame(c.r, hdr, limit)
	return frameResult{m: m, err: err}
}

func (c *pipeConn) readMsg(limit int) (message, *os.File, error) {
	c.mu.Lock()
	broken := c.broken
	c.mu.Unlock()
	if broken {
		return message{}, nil, errBrokenConn
	}
	ch := make(chan frameResult, 1)
	go func() { ch <- c.readFrame(limit) }()
	for {
		c.mu.Lock()
		d, changed := c.deadline, c.changed
		c.mu.Unlock()
		var timer <-chan time.Time
		var t *time.Timer
		if !d.IsZero() {
			t = time.NewTimer(time.Until(d))
			timer = t.C
		}
		select {
		case r := <-ch:
			if t != nil {
				t.Stop()
			}
			return c.adopt(r)
		case <-timer:
			c.mu.Lock()
			c.broken = true
			c.mu.Unlock()
			return message{}, nil, os.ErrDeadlineExceeded
		case <-changed:
			if t != nil {
				t.Stop()
			}
		}
	}
}

// adopt turns a scan's handle into the file it names (worker side).
func (c *pipeConn) adopt(r frameResult) (message, *os.File, error) {
	if r.err != nil {
		return message{}, nil, r.err
	}
	var f *os.File
	if c.worker && r.m.Handle != 0 {
		f = os.NewFile(uintptr(r.m.Handle), "scan-input")
	}
	return r.m, f, nil
}

func (c *pipeConn) close() error {
	err := c.w.Close()
	if rerr := c.r.Close(); err == nil {
		err = rerr
	}
	return err
}
