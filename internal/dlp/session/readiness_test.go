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

type fakeReadiness struct {
	mu    sync.Mutex
	state string
}

func (f *fakeReadiness) get() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, ""
}

func (f *fakeReadiness) set(s string) {
	f.mu.Lock()
	f.state = s
	f.mu.Unlock()
}

// Notification readiness (#323) reaches the service per session, follows
// changes, and makes a hidden notification a failure, while Do Not Disturb
// still counts as shown.
func TestHelperReportsReadiness(t *testing.T) {
	old := channelRecheck
	channelRecheck = 20 * time.Millisecond
	t.Cleanup(func() { channelRecheck = old })

	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), nil)
	t.Cleanup(hub.Stop)

	rd := &fakeReadiness{state: "supported"}
	n := &fakeNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunHelper(ctx, HelperOptions{Addr: addr, Version: "test", Channels: []channel.Channel{&fakeChannel{}},
			Notify: n.Notify, Readiness: rd.get, Backoff: func(int) time.Duration { return 20 * time.Millisecond }})
	}()
	t.Cleanup(func() { cancel(); <-done })

	readiness := func() string {
		s := hub.Sessions()
		if len(s) != 1 {
			return ""
		}
		return s[0].Capabilities[CapNotifications]
	}
	eventually(t, "readiness at hello", func() bool { return readiness() == "supported" })

	// a change is reported without any policy or notification
	rd.set("disabled:app")
	eventually(t, "the change to reach the service", func() bool { return readiness() == "disabled:app" })

	res := hub.Notify(context.Background(), ipc.Notify{Title: "t", Message: "m"})
	if len(res) != 1 || !strings.Contains(res[0].Err, "disabled:app") || res[0].Readiness != "disabled:app" {
		t.Fatalf("hidden notification = %+v", res)
	}

	// one session: its readiness, and a notification to it alone (#336)
	sid := hub.Sessions()[0].SessionID
	if st, ok := hub.SessionReadiness(sid); !ok || st != "disabled:app" {
		t.Fatalf("SessionReadiness = %q %v", st, ok)
	}
	if _, ok := hub.SessionReadiness("no-such-session"); ok {
		t.Fatal("readiness for a session without a helper")
	}
	rd.set("supported")
	if err := hub.NotifySession(context.Background(), sid, ipc.Notify{Title: "Blocked", Message: "m", Level: ipc.LevelWarning}); err != nil {
		t.Fatalf("NotifySession: %v", err)
	}
	if err := hub.NotifySession(context.Background(), "no-such-session", ipc.Notify{Title: "t", Message: "m"}); err != ErrNoHelper {
		t.Fatalf("no helper: %v", err)
	}

	// read again just before showing: no wait for the next minute
	channelRecheck = time.Hour
	rd.set("dnd")
	res = hub.Notify(context.Background(), ipc.Notify{Title: "t", Message: "m"})
	if len(res) != 1 || res[0].Err != "" || res[0].Readiness != "dnd" {
		t.Fatalf("dnd notification = %+v", res)
	}
}
