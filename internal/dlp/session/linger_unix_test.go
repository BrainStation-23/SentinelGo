//go:build linux || darwin

package session

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A refused endpoint that never hangs up doesn't hold the helper: it leaves
// after refusedLinger, having sent nothing.
func TestLingerRefusedBounded(t *testing.T) {
	prev := refusedLinger
	refusedLinger = 100 * time.Millisecond
	t.Cleanup(func() { refusedLinger = prev })

	addr := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	got := make(chan int, 1)
	go func() {
		s, err := l.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer func() { _ = s.Close() }()
		_, _ = s.Write([]byte("not a policy")) // drained and discarded
		buf := make([]byte, 16)
		n, _ := s.Read(buf) // EOF from CloseWrite; held open afterwards
		got <- n
		time.Sleep(time.Second)
	}()

	c, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	lingerRefused(c)
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Errorf("lingerRefused waited %v for an endpoint that doesn't hang up", d)
	}
	if n := <-got; n != 0 {
		t.Errorf("endpoint read %d bytes from a refusing helper, want 0", n)
	}
}

// A connection without a write half to close is left as it is.
func TestLingerRefusedNotHalfClosable(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	lingerRefused(a) // must return at once, not block on b
}
