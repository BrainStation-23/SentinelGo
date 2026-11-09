package session

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// handoffChannel hands one file to the service each time it runs.
type handoffChannel struct {
	released atomic.Int32
	handed   atomic.Int32
}

func (c *handoffChannel) Name() string                  { return policy.ChannelClipboard }
func (c *handoffChannel) Supported() channel.Capability { return channel.Supported() }
func (c *handoffChannel) Run(ctx context.Context, _ *policy.Compiled, sink channel.EventSink) error {
	h, ok := sink.(FileHandoff)
	if !ok {
		return channel.ErrUnsupported
	}
	c.handed.Add(1)
	h.HandOff(ipc.UserFile{Handle: 42, Channel: policy.ChannelFileNetworkShare, Root: `Z:\`}, func() { c.released.Add(1) })
	<-ctx.Done()
	return ctx.Err()
}

// A helper hands a file over: the hub gives it to the receiver with the
// helper's OS identity, acks it, and the helper releases its handle.
func TestHandOffRoundTrip(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	var mu sync.Mutex
	var got []ipc.UserFile
	var from ipc.Identity
	hub.SetFileReceiver(func(id ipc.Identity, f ipc.UserFile) {
		mu.Lock()
		defer mu.Unlock()
		got, from = append(got, f), id
	})
	hub.Apply(context.Background(), compiled(t, "v1", true))
	t.Cleanup(hub.Stop)
	ch := &handoffChannel{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{ch},
			Backoff: func(int) time.Duration { return 20 * time.Millisecond }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "the hand-off", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 })
	eventually(t, "the release", func() bool { return ch.released.Load() == 1 })
	mu.Lock()
	f := got[0]
	mu.Unlock()
	if f.Handle != 42 || f.ID == "" || f.Channel != policy.ChannelFileNetworkShare || from.PID <= 0 || from.User == "" {
		t.Errorf("file %+v from %+v", f, from)
	}
}

// Without an ack (no receiver answer, or the service is gone), the helper
// still releases: on timeout, on disconnect, and right away when it isn't
// connected or too many wait.
func TestHandOffReleases(t *testing.T) {
	prevTimeout, prevMax := handoffTimeout, maxHandoffs
	t.Cleanup(func() { handoffTimeout, maxHandoffs = prevTimeout, prevMax })
	handoffTimeout = 50 * time.Millisecond
	r := &helperRuntime{}
	var released atomic.Int32
	rel := func() { released.Add(1) }

	r.HandOff(ipc.UserFile{}, rel) // not connected
	if released.Load() != 1 {
		t.Fatalf("not released while disconnected: %d", released.Load())
	}
	svc, helperEnd := pipePair(t)
	r.attach(helperEnd)
	go drain(svc)
	r.HandOff(ipc.UserFile{ID: "a"}, rel)
	eventually(t, "the timeout release", func() bool { return released.Load() == 2 })
	r.released("a") // a late ack: nothing more
	if released.Load() != 2 {
		t.Errorf("released twice: %d", released.Load())
	}
	handoffTimeout = time.Hour
	r.HandOff(ipc.UserFile{ID: "b"}, rel)
	r.detach()
	if released.Load() != 3 {
		t.Errorf("not released on disconnect: %d", released.Load())
	}
	r.attach(helperEnd)
	maxHandoffs = 0
	r.HandOff(ipc.UserFile{ID: "c"}, rel)
	if released.Load() != 4 {
		t.Errorf("not released over the cap: %d", released.Load())
	}
}

// pipePair is an in-memory service/helper connection.
func pipePair(t *testing.T) (svc, helperEnd net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// drain reads and drops whatever the helper sends.
func drain(c net.Conn) { _, _ = io.Copy(io.Discard, c) }
