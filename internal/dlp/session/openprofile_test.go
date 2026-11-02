package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

type fakeOpener struct {
	mu   sync.Mutex
	name string
	data []byte
	err  error
}

func (f *fakeOpener) Open(name string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.name, f.data = name, data
	return f.err
}

func startProfileHelper(t *testing.T, addr string, open func(string, []byte) error, n *fakeNotifier) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{&fakeChannel{}},
			Notify: n.Notify, OpenProfile: open, Backoff: func(int) time.Duration { return 20 * time.Millisecond }})
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// OpenProfile reaches only the named session's helper, which opens the
// profile and then shows the instructions (#350).
func TestOpenProfile(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	op, n := &fakeOpener{}, &fakeNotifier{}
	startProfileHelper(t, addr, op.Open, n)
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	sid := hub.Sessions()[0].SessionID

	err := hub.OpenProfile(context.Background(), sid, ipc.OpenProfile{Name: "E.mobileconfig", Data: []byte("<?xml profile"), Title: "Enroll", Message: "Install it"})
	if err != nil {
		t.Fatalf("OpenProfile: %v", err)
	}
	op.mu.Lock()
	if op.name != "E.mobileconfig" || string(op.data) != "<?xml profile" {
		t.Errorf("opened %q %q", op.name, op.data)
	}
	op.mu.Unlock()
	if n.count() != 1 || !strings.HasPrefix(n.shown[0], ipc.LevelWarning+"|Enroll|") {
		t.Errorf("instructions shown = %v", n.shown)
	}

	if err := hub.OpenProfile(context.Background(), sid+"-other", ipc.OpenProfile{Name: "x"}); !errors.Is(err, ErrNoHelper) {
		t.Errorf("unknown session: %v, want ErrNoHelper", err)
	}
}

// A helper that can't open profiles, or fails to, says so; nothing is shown.
func TestOpenProfileFailures(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	n := &fakeNotifier{}
	op := &fakeOpener{err: errors.New("open: exit status 1")}
	startProfileHelper(t, addr, op.Open, n)
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	sid := hub.Sessions()[0].SessionID
	if err := hub.OpenProfile(context.Background(), sid, ipc.OpenProfile{Name: "x", Title: "t"}); err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("failing opener: %v", err)
	}
	if n.count() != 0 {
		t.Error("instructions shown for a profile that wasn't opened")
	}
}

func TestOpenProfileHelperWithoutOpener(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)
	startProfileHelper(t, addr, nil, &fakeNotifier{})
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	err := hub.OpenProfile(context.Background(), hub.Sessions()[0].SessionID, ipc.OpenProfile{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "can't open configuration profiles") {
		t.Errorf("helper without opener: %v", err)
	}
}
