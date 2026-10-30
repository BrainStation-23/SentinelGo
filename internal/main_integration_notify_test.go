package internal

import (
	"context"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/dlp"
	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/session"
	"sentinelgo/internal/scheduler"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/taskstore"
)

// Tests never start helpers on the machine running them.
func init() {
	newSessions = func(channel.EventSink) session.Service { return &fakeSessions{} }
}

// fakeSessions stands in for the session helper service.
type fakeSessions struct {
	mu       sync.Mutex
	applied  []*policy.Compiled // nil entries: "no policy"
	stops    int
	notified []ipc.Notify
	results  []session.NotifyResult
	infos    []session.Info
}

func (f *fakeSessions) Apply(_ context.Context, p *policy.Compiled) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, p)
}

func (f *fakeSessions) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeSessions) Sessions() []session.Info {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.infos
}

func (f *fakeSessions) Notify(_ context.Context, n ipc.Notify) []session.NotifyResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified = append(f.notified, n)
	return f.results
}

// The helpers run, and notify-user reaches them, whatever DLP's state: off
// in config.json, or on without a policy (#301).
func TestNotifyUser_WithoutDLP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dlpEnabled bool
		state      dlp.State
	}{
		{"dlp_enabled false", false, dlp.StateDisabledLocal},
		{"no policy", true, dlp.StateNoPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := miTestConfig(t)
			cfg.DLPEnabled = tc.dlpEnabled
			mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())
			mi.startDLP(context.Background())
			t.Cleanup(func() { _ = mi.Stop() })
			if got := mi.dlpManager.State(); got != tc.state {
				t.Fatalf("DLP state = %s, want %s", got, tc.state)
			}
			fs := mi.sessions.(*fakeSessions)
			fs.results = []session.NotifyResult{{User: "alice", SessionID: "501"}}
			fs.infos = []session.Info{
				{User: "alice", State: "idle", SessionID: "501", Capabilities: map[string]string{"clipboard": "supported"}},
				{User: "bob", State: "start_failed", SessionID: "502", LastError: "launchctl bootstrap: exit status 5"},
			}

			task := taskstore.Task{Payload: map[string]interface{}{"title": "Reboot", "message": "Tonight at 22:00", "level": "critical"}}
			note, err := native.Find("notify-user").Run(context.Background(), cfg, task)
			if err != nil {
				t.Fatal(err)
			}
			want := "Shown to 1 session (alice); no session helper connected for bob (start_failed: launchctl bootstrap: exit status 5)"
			if note != want {
				t.Errorf("note = %q, want %q", note, want)
			}
			fs.mu.Lock()
			defer fs.mu.Unlock()
			if len(fs.applied) == 0 || fs.applied[0] != nil {
				t.Errorf("helpers not started without a policy: %v", fs.applied)
			}
			if fs.stops != 0 {
				t.Errorf("DLP being off stopped the helpers (%d stops)", fs.stops)
			}
			if len(fs.notified) != 1 || fs.notified[0].Title != "Reboot" || fs.notified[0].Level != ipc.LevelCritical {
				t.Errorf("notified = %+v", fs.notified)
			}
		})
	}
}

// Stop removes the hook and stops the helpers, once.
func TestNotifyUser_StopRemovesHook(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.DLPEnabled = false
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())
	mi.startDLP(context.Background())
	fs := mi.sessions.(*fakeSessions)
	if err := mi.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := mi.Stop(); err != nil {
		t.Fatal(err)
	}
	if fs.stops != 1 {
		t.Errorf("helpers stopped %d times, want 1", fs.stops)
	}
	task := taskstore.Task{Payload: map[string]interface{}{"title": "t", "message": "m"}}
	if _, err := native.Find("notify-user").Run(context.Background(), cfg, task); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("after Stop: err = %v", err)
	}
}

// Nobody signed in: the task fails and nothing is kept for later.
func TestNotifyUser_NoUser(t *testing.T) {
	cfg := miTestConfig(t)
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())
	mi.startDLP(context.Background())
	t.Cleanup(func() { _ = mi.Stop() })
	task := taskstore.Task{Payload: map[string]interface{}{"title": "t", "message": "m"}}
	_, err := native.Find("notify-user").Run(context.Background(), cfg, task)
	if err == nil || err.Error() != "no user is signed in; nothing was shown" {
		t.Errorf("err = %v", err)
	}
}
