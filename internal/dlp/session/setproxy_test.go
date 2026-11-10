package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/desktopproxy"
)

// fakeProxy records what the helper set; err is returned for a non-empty URL.
type fakeProxy struct {
	mu   sync.Mutex
	urls []string
	err  error
}

func (f *fakeProxy) set(u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls = append(f.urls, u)
	if u != "" {
		return f.err
	}
	return nil
}

func (f *fakeProxy) last() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.urls) == 0 {
		return "<none>", 0
	}
	return f.urls[len(f.urls)-1], len(f.urls)
}

func runProxyHelper(t *testing.T, addr string, setProxy func(string) error) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{&fakeChannel{}},
			SetProxy: setProxy, Backoff: func(int) time.Duration { return 20 * time.Millisecond }})
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return stop
}

// SetProxy reaches every helper, records each session's outcome in its
// capabilities, and the helper puts the user's setting back when it loses
// the service (#426).
func TestHubSetProxy(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	if rs := hub.SetProxy(context.Background(), "http://x/proxy.pac"); len(rs) != 0 {
		t.Fatalf("no helpers, got %v", rs)
	}

	fp := &fakeProxy{}
	stop := runProxyHelper(t, addr, fp.set)
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })

	const pac = "http://127.0.0.1:3129/proxy.pac"
	rs := hub.SetProxy(context.Background(), pac)
	if len(rs) != 1 || rs[0].Reason != "" {
		t.Fatalf("results %+v", rs)
	}
	if u, _ := fp.last(); u != pac {
		t.Errorf("helper set %q", u)
	}
	if got := hub.Sessions()[0].Capabilities[CapUploadRedirect]; got != "active" {
		t.Errorf("session redirect %q", got)
	}

	fp.mu.Lock()
	fp.err = fmt.Errorf("%w: gnome mode manual", desktopproxy.ErrExistingProxy)
	fp.mu.Unlock()
	rs = hub.SetProxy(context.Background(), pac)
	if len(rs) != 1 || rs[0].Reason != "existing_proxy" {
		t.Fatalf("results %+v", rs)
	}
	if got := hub.Sessions()[0].Capabilities[CapUploadRedirect]; got != "unsupported:existing_proxy" {
		t.Errorf("session redirect %q", got)
	}

	rs = hub.SetProxy(context.Background(), "")
	if len(rs) != 1 || rs[0].Reason != "" || hub.Sessions()[0].Capabilities[CapUploadRedirect] != "inactive" {
		t.Fatalf("clear: %+v %v", rs, hub.Sessions()[0].Capabilities)
	}

	// The helper restores when it leaves.
	fp.mu.Lock()
	fp.urls = nil
	fp.mu.Unlock()
	stop()
	if u, n := fp.last(); u != "" || n == 0 {
		t.Errorf("not cleared on exit: %q (%d calls)", u, n)
	}
}

// A helper without a desktop proxy (Windows, macOS) says so.
func TestHubSetProxyUnsupportedHelper(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)
	runProxyHelper(t, addr, nil)
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	rs := hub.SetProxy(context.Background(), "http://x/proxy.pac")
	if len(rs) != 1 || rs[0].Reason != "unsupported_platform" {
		t.Fatalf("results %+v", rs)
	}
}

func TestPerSession(t *testing.T) {
	for c, want := range map[string]bool{CapNotifications: true, CapUploadRedirect: true, "clipboard": false} {
		if PerSession(c) != want {
			t.Errorf("%s: %v", c, !want)
		}
	}
}
