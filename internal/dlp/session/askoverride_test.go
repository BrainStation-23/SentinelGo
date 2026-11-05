package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// The service asks one session's helper what to do about a blocked file;
// the helper's dialog answer comes back (#336).
func TestAskOverrideRoundTrip(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	asked := make(chan ipc.AskOverride, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{&fakeChannel{}},
			Backoff: func(int) time.Duration { return 20 * time.Millisecond },
			AskOverride: func(_ context.Context, a ipc.AskOverride) (string, string, error) {
				asked <- a
				return "override", "client deadline", nil
			}})
	}()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	sid := hub.Sessions()[0].SessionID

	ans, err := hub.AskOverride(context.Background(), sid, ipc.AskOverride{Title: "Blocked", Message: "m", CanOverride: true})
	if err != nil || ans.Choice != "override" || ans.Reason != "client deadline" {
		t.Fatalf("answer %+v %v", ans, err)
	}
	if a := <-asked; !a.CanOverride || a.CanRequest || a.Title != "Blocked" {
		t.Fatalf("asked %+v", a)
	}
	if _, err := hub.AskOverride(context.Background(), "no-such-session", ipc.AskOverride{}); !errors.Is(err, ErrNoHelper) {
		t.Fatalf("no helper: %v", err)
	}
}

// A helper that can't show the dialog answers cancel with an error, never
// hangs the service.
func TestAskOverrideWithoutDialog(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)
	startHelper(t, addr, &fakeChannel{}, nil)
	eventually(t, "the helper to connect", func() bool { return connectedHelpers(hub) == 1 })
	ans, err := hub.AskOverride(context.Background(), hub.Sessions()[0].SessionID, ipc.AskOverride{CanOverride: true})
	if err == nil || ans.Choice != "cancel" {
		t.Fatalf("answer %+v %v", ans, err)
	}
}
