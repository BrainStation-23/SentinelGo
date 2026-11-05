package filedlp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
)

type fakeUserNotifier struct {
	mu        sync.Mutex
	readiness map[string]string // uid → state; absent: no helper
	shown     []string          // uid|title|body
}

func (f *fakeUserNotifier) SessionReadiness(uid string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.readiness[uid]
	return s, ok
}

func (f *fakeUserNotifier) NotifySession(_ context.Context, uid, title, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = append(f.shown, uid+"|"+title+"|"+body)
	return nil
}

func (f *fakeUserNotifier) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.shown...)
}

func fastNotices(t *testing.T) {
	t.Helper()
	w, d := noticeWindow, noticeDedup
	noticeWindow = 30 * time.Millisecond
	t.Cleanup(func() { noticeWindow, noticeDedup = w, d })
}

// Copying a folder gives one notification; a retry of the same file isn't
// counted again; the text never carries a matched value.
func TestNotices_AggregateAndDedup(t *testing.T) {
	fastNotices(t)
	fn := &fakeUserNotifier{readiness: map[string]string{"1000": "supported"}}
	s := newNotices(fn)
	r := usbRequest()
	f := []detect.Finding{cardFinding()}
	for i, sha := range []string{"a", "b", "c", "a"} {
		r.Path = "/media/alice/KINGSTON/f" + string(rune('0'+i)) + ".xlsx"
		r.Proc.UID = "1000"
		if !s.report(r, noticeBlocked, sha, f, "SentinelOps blocked this file: pii.credit_card") {
			t.Fatal("not told")
		}
	}
	s.wait()
	got := fn.all()
	if len(got) != 1 {
		t.Fatalf("%d notifications: %v", len(got), got)
	}
	if !strings.Contains(got[0], "blocked 3 files") || !strings.Contains(got[0], `the USB drive "KINGSTON"`) ||
		strings.Contains(got[0], "4111") {
		t.Fatalf("text %q", got[0])
	}
}

func TestNotices_WhoCanBeTold(t *testing.T) {
	fastNotices(t)
	fn := &fakeUserNotifier{readiness: map[string]string{"1000": "disabled:app", "1001": "dnd"}}
	s := newNotices(fn)
	r := usbRequest()
	for uid, want := range map[string]bool{"1000": false, "1001": true, "1002": false, "": false} {
		r.Proc.UID = uid
		if got := s.report(r, noticeWarned, "x"+uid, nil, ""); got != want {
			t.Errorf("uid %q: told %v, want %v", uid, got, want)
		}
	}
	s.wait()
	if n := len(fn.all()); n != 1 {
		t.Fatalf("%d notifications", n)
	}
	var none *notices
	if none.report(r, noticeBlocked, "", nil, "") {
		t.Fatal("nil notices told someone")
	}
}

func TestNoticeText(t *testing.T) {
	one := &noticeBatch{files: []string{"plan.txt"}, detectors: map[string]bool{"pii.credit_card": true}, message: "No: pii.credit_card"}
	for kind, want := range map[string]string{
		noticeBlocked: `No: pii.credit_card ("plan.txt" to a USB drive)`,
		noticeRemoved: `"plan.txt" copied to a USB drive contains pii.credit_card and was removed from it`,
		noticeWarned:  `"plan.txt" copied to a USB drive contains pii.credit_card. This was logged.`,
	} {
		if _, body := noticeText(noticeKey{kind: kind, dest: "a USB drive"}, one); !strings.Contains(body, want) {
			t.Errorf("%s: %q", kind, body)
		}
	}
	two := &noticeBatch{files: []string{"a", "b"}, detectors: map[string]bool{}}
	if title, body := noticeText(noticeKey{kind: noticeRemoved, dest: "x"}, two); title != "SentinelOps removed 2 files" || !strings.Contains(body, "2 files copied to x contain content that couldn't be checked and were removed") {
		t.Errorf("%q %q", title, body)
	}
	if destLabel(Destination{Type: TypeNetworkShare, ShareHost: "fs1"}) != "the network share on fs1" {
		t.Error("share label")
	}
}

// The decider sets user_notified on what it tells about, and nothing on a
// plain monitored event.
func TestDecider_UserNotified(t *testing.T) {
	fastNotices(t)
	match := filescan.Result{Status: filescan.StatusScanned, SHA256: "s1", Findings: []detect.Finding{cardFinding()}}
	for _, tc := range []struct {
		action   string
		canBlock bool
		want     *bool
	}{
		{"block", true, ptrTo(true)},
		{"warn", false, ptrTo(true)},
		{"monitor", false, nil},
	} {
		fn := &fakeUserNotifier{readiness: map[string]string{"1000": "supported"}}
		sink := &recordingSink{}
		d := NewDecider(&fakeScanner{res: match}, sink)
		d.SetUserNotifier(fn)
		d.Apply(compile(t, strings.Replace(testBundle("masked", `"enabled": true, "channels": {"file.removable": true}, "audit_only": false`, ""),
			`"action": "block"`, `"action": "`+tc.action+`"`, 1)))
		d.Decide(context.Background(), usbRequest(), tc.canBlock)
		d.notices.wait()
		evs := sink.events()
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", tc.action, len(evs))
		}
		got := evs[0].UserNotified
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: user_notified %v", tc.action, got)
		}
		if tc.want != nil && len(fn.all()) != 1 {
			t.Errorf("%s: %d notifications", tc.action, len(fn.all()))
		}
		if tc.action == "block" && evs[0].Action != events.ActionBlocked {
			t.Errorf("block: action %q", evs[0].Action)
		}
	}
}
