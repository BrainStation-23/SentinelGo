package session

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// OpenURL reaches the session's helper, which opens only enrollment links
// (#356).
func TestOpenURL(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	var mu sync.Mutex
	var opened []string
	n := &fakeNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{&fakeChannel{}}, Notify: n.Notify,
			OpenURL: func(u string) error { mu.Lock(); opened = append(opened, u); mu.Unlock(); return nil },
			Backoff: func(int) time.Duration { return 20 * time.Millisecond }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	sid := hub.Sessions()[0].SessionID

	link := "ms-device-enrollment:?mode=mdm&username=a%40b.com"
	if err := hub.OpenURL(context.Background(), sid, ipc.OpenURL{URL: link, Title: "Enroll", Message: "Sign in"}); err != nil {
		t.Fatalf("OpenURL: %v", err)
	}
	if err := hub.OpenURL(context.Background(), sid, ipc.OpenURL{URL: "https://evil.example.com"}); err == nil || !strings.Contains(err.Error(), "enrollment links only") {
		t.Errorf("non-enrollment URL: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 1 || opened[0] != link || n.count() != 1 {
		t.Errorf("opened %v, notifications %d", opened, n.count())
	}
}
