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
	mu                   sync.Mutex
	name, title, message string
	data                 []byte
	err                  error
}

func (f *fakeOpener) Open(name string, data []byte, title, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.name, f.data, f.title, f.message = name, data, title, message
	return f.err
}

func startProfileHelper(t *testing.T, addr string, open func(string, []byte, string, string) error, n *fakeNotifier) {
	t.Helper()
	startHelperWith(t, HelperOptions{Addr: addr, Notify: n.Notify, OpenProfile: open})
}

func startHelperWith(t *testing.T, o HelperOptions) {
	t.Helper()
	o.Version, o.Channels = "test", []channel.Channel{&fakeChannel{}}
	o.Backoff = func(int) time.Duration { return 20 * time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, o)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// OpenProfile reaches only the named session's helper, which opens the
// profile with the instructions (#350, #545). The opener shows them itself,
// as a dialog, so no notification goes out.
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
	if op.name != "E.mobileconfig" || string(op.data) != "<?xml profile" || op.title != "Enroll" || op.message != "Install it" {
		t.Errorf("opened %q %q %q %q", op.name, op.data, op.title, op.message)
	}
	op.mu.Unlock()
	if n.count() != 0 {
		t.Errorf("notification shown as well: %v", n.shown)
	}

	if err := hub.OpenProfile(context.Background(), sid+"-other", ipc.OpenProfile{Name: "x"}); !errors.Is(err, ErrNoHelper) {
		t.Errorf("unknown session: %v, want ErrNoHelper", err)
	}
}

// A helper that can't open profiles, or fails to, says so.
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

// OfferEnroll reaches the session's helper and comes back with the user's
// choice; a helper that can't ask answers later with an error (#545).
func TestOfferEnroll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offer  func(context.Context, string, string) (bool, error)
		want   bool
		errHas string
	}{
		{"enroll now", func(_ context.Context, title, msg string) (bool, error) { return title == "T" && msg == "M", nil }, true, ""},
		{"later", func(context.Context, string, string) (bool, error) { return false, nil }, false, ""},
		{"dialog failed", func(context.Context, string, string) (bool, error) {
			return true, errors.New("osascript: exit status 1")
		}, false, "exit status 1"},
		{"can't ask", nil, false, "can't offer enrollment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := testAddress(t)
			hub := NewHub(addr, &recordingSink{})
			hub.Apply(context.Background(), nil)
			t.Cleanup(hub.Stop)
			startHelperWith(t, HelperOptions{Addr: addr, OfferEnroll: tc.offer})
			eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })

			yes, err := hub.OfferEnroll(context.Background(), hub.Sessions()[0].SessionID, ipc.OfferEnroll{Title: "T", Message: "M"})
			if yes != tc.want {
				t.Errorf("enroll = %v, want %v", yes, tc.want)
			}
			if (tc.errHas == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.errHas)) {
				t.Errorf("err = %v, want %q", err, tc.errHas)
			}
		})
	}

	hub := NewHub(testAddress(t), &recordingSink{})
	if _, err := hub.OfferEnroll(context.Background(), "nobody", ipc.OfferEnroll{}); !errors.Is(err, ErrNoHelper) {
		t.Errorf("no helper: %v", err)
	}
}
