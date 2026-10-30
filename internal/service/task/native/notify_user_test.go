package native

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"sentinelgo/internal/taskstore"
)

func TestNotifyUserSlugs(t *testing.T) {
	for _, slug := range []string{"notify-user", "notify_user"} {
		if Find(slug) == nil {
			t.Errorf("%s not registered", slug)
		}
	}
}

func TestParseNotification(t *testing.T) {
	long := strings.Repeat("é", 300)
	for _, tc := range []struct {
		name    string
		payload map[string]interface{}
		want    DesktopNotification
		wantErr string
	}{
		{name: "minimal", payload: map[string]interface{}{"title": " Reboot ", "message": " Tonight at 22:00 "},
			want: DesktopNotification{Title: "Reboot", Message: "Tonight at 22:00", Level: NotifyLevelInfo}},
		{name: "level and unknown keys", payload: map[string]interface{}{"title": "t", "message": "m", "level": "Critical", "extra": 1},
			want: DesktopNotification{Title: "t", Message: "m", Level: NotifyLevelCritical}},
		{name: "warning", payload: map[string]interface{}{"title": "t", "message": "m", "level": "warning"},
			want: DesktopNotification{Title: "t", Message: "m", Level: NotifyLevelWarning}},
		{name: "unknown level is info", payload: map[string]interface{}{"title": "t", "message": "m", "level": "panic"},
			want: DesktopNotification{Title: "t", Message: "m", Level: NotifyLevelInfo}},
		{name: "non-string level is info", payload: map[string]interface{}{"title": "t", "message": "m", "level": 3},
			want: DesktopNotification{Title: "t", Message: "m", Level: NotifyLevelInfo}},
		{name: "missing title", payload: map[string]interface{}{"message": "m"}, wantErr: "payload.title is required"},
		{name: "null title", payload: map[string]interface{}{"title": nil, "message": "m"}, wantErr: "payload.title is required"},
		{name: "empty title", payload: map[string]interface{}{"title": "   ", "message": "m"}, wantErr: "payload.title is empty"},
		{name: "missing message", payload: map[string]interface{}{"title": "t"}, wantErr: "payload.message is required"},
		{name: "empty message", payload: map[string]interface{}{"title": "t", "message": ""}, wantErr: "payload.message is empty"},
		{name: "non-string message", payload: map[string]interface{}{"title": "t", "message": 42}, wantErr: "payload.message must be a string"},
		{name: "nil payload", payload: nil, wantErr: "payload.title is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNotification(tc.payload)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}

	got, err := parseNotification(map[string]interface{}{"title": long, "message": long})
	if err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(got.Title); n != maxNotifyTitle || !strings.HasSuffix(got.Title, "…") {
		t.Errorf("title cut to %d runes: %q", n, got.Title)
	}
	if n := utf8.RuneCountInString(got.Message); n != maxNotifyMessage {
		t.Errorf("message cut to %d runes", n)
	}
}

func TestNotifyUser(t *testing.T) {
	h := Find("notify-user")
	t.Cleanup(func() { SetUserNotifier(nil) })
	task := taskstore.Task{Payload: map[string]interface{}{"title": "Reboot", "message": "Tonight", "level": "warning"}}

	SetUserNotifier(nil)
	if _, err := h.Run(context.Background(), nil, task); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("without the hook: err = %v", err)
	}

	// An invalid payload never reaches the sessions.
	called := false
	SetUserNotifier(func(context.Context, DesktopNotification) ([]NotifyResult, []string) { called = true; return nil, nil })
	if _, err := h.Run(context.Background(), nil, taskstore.Task{Payload: map[string]interface{}{"title": "t"}}); err == nil || called {
		t.Errorf("invalid payload: err = %v, shown = %v", err, called)
	}

	var got DesktopNotification
	for _, tc := range []struct {
		name      string
		results   []NotifyResult
		unreached []string
		note      string
		err       string
	}{
		{name: "two sessions", results: []NotifyResult{{User: "alice"}, {User: "bob"}}, note: "Shown to 2 sessions (alice, bob)"},
		{name: "one shown, one failed, one not connected",
			results:   []NotifyResult{{User: "alice"}, {User: "bob", Err: "exit status 1"}},
			unreached: []string{"carol (starting)"},
			note:      "Shown to 1 session (alice); not shown to bob: exit status 1; no session helper connected for carol (starting)"},
		{name: "nobody signed in", err: "no user is signed in; nothing was shown"},
		{name: "every helper failed", results: []NotifyResult{{User: "alice", Err: "notify-send not found"}}, err: "nothing was shown: alice: notify-send not found"},
		{name: "helpers not connected", unreached: []string{"alice (start_failed: launchctl bootstrap: exit status 5)"},
			err: "nothing was shown: no session helper connected for alice (start_failed: launchctl bootstrap: exit status 5)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetUserNotifier(func(_ context.Context, n DesktopNotification) ([]NotifyResult, []string) {
				got = n
				return tc.results, tc.unreached
			})
			note, err := h.Run(context.Background(), nil, task)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Errorf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || note != tc.note {
				t.Errorf("note = %q, err = %v; want %q", note, err, tc.note)
			}
		})
	}
	if got != (DesktopNotification{Title: "Reboot", Message: "Tonight", Level: NotifyLevelWarning}) {
		t.Errorf("hook got %+v", got)
	}
}

// The wait for the sessions is bounded.
func TestNotifyUser_Deadline(t *testing.T) {
	prev := notifyWait
	notifyWait = 0
	t.Cleanup(func() { notifyWait = prev; SetUserNotifier(nil) })
	SetUserNotifier(func(ctx context.Context, _ DesktopNotification) ([]NotifyResult, []string) {
		<-ctx.Done()
		return []NotifyResult{{User: "alice", Err: errors.New("no answer").Error()}}, nil
	})
	task := taskstore.Task{Payload: map[string]interface{}{"title": "t", "message": "m"}}
	if _, err := Find("notify_user").Run(context.Background(), nil, task); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Errorf("err = %v", err)
	}
}
