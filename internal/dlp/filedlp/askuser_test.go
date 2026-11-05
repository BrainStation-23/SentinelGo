package filedlp

import (
	"context"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/dlp/events"
)

// fakeAsker is a notifier whose user answers the dialog with choice/reason.
type fakeAsker struct {
	fakeUserNotifier
	choice, reason string
	mu             sync.Mutex
	asked          []string // "override,request" flags per dialog
}

func (f *fakeAsker) AskOverride(_ context.Context, uid, title, msg string, canOverride, canRequest bool) (string, string, error) {
	f.mu.Lock()
	f.asked = append(f.asked, strings.Join([]string{uid, boolStr(canOverride), boolStr(canRequest), msg}, "|"))
	f.mu.Unlock()
	return f.choice, f.reason, nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func askDecider(t *testing.T, fa *fakeAsker, bundleExtra string) (*Decider, *recordingSink, *[]ExceptionRequest) {
	t.Helper()
	fastNotices(t)
	d, sink := overrideDecider(t, overrideBundle(bundleExtra))
	d.SetUserNotifier(fa)
	var reqs []ExceptionRequest
	var mu sync.Mutex
	d.SetExceptionRequester(func(_ context.Context, r ExceptionRequest) error {
		mu.Lock()
		reqs = append(reqs, r)
		mu.Unlock()
		return nil
	})
	return d, sink, &reqs
}

func uidRequest() Request {
	r := usbRequest()
	r.Proc.UID = "1000"
	return r
}

// The user goes ahead with a reason: the override is recorded and they are
// told they can copy the file now.
func TestAsk_Override(t *testing.T) {
	fa := &fakeAsker{fakeUserNotifier: fakeUserNotifier{readiness: map[string]string{"1000": "supported"}}, choice: "override", reason: "client deadline"}
	d, sink, _ := askDecider(t, fa, "")
	v := d.Decide(context.Background(), uidRequest(), true)
	d.asking.wg.Wait()
	if !v.Block || len(fa.asked) != 1 || !strings.HasPrefix(fa.asked[0], "1000|1|1|") || strings.Contains(fa.asked[0], "4111") {
		t.Fatalf("verdict %+v asked %v", v, fa.asked)
	}
	evs := sink.events()
	if len(evs) != 2 || evs[0].Action != events.ActionBlocked || evs[0].UserNotified == nil || !*evs[0].UserNotified ||
		evs[1].Action != events.ActionOverridden || evs[1].Override.Justification != "client deadline" {
		t.Fatalf("events %+v", evs)
	}
	if shown := fa.all(); len(shown) != 1 || !strings.Contains(shown[0], "You can copy") {
		t.Fatalf("result %v", shown)
	}
}

// The user asks IT: the request carries the policy, the block, the file's
// hash and the reason.
func TestAsk_Request(t *testing.T) {
	fa := &fakeAsker{fakeUserNotifier: fakeUserNotifier{readiness: map[string]string{"1000": "supported"}}, choice: "request", reason: "needed for the audit"}
	d, sink, reqs := askDecider(t, fa, "")
	v := d.Decide(context.Background(), uidRequest(), true)
	d.asking.wg.Wait()
	if len(*reqs) != 1 {
		t.Fatalf("requests %+v", *reqs)
	}
	r := (*reqs)[0]
	if r.PolicyID != "p1" || r.Channel != "file.removable" || r.EventID != v.EventID || r.SHA256 != "aa11" || r.Justification != "needed for the audit" {
		t.Fatalf("request %+v", r)
	}
	if len(sink.events()) != 1 {
		t.Fatal("a request recorded an override")
	}
	if shown := fa.all(); len(shown) != 1 || !strings.Contains(shown[0], "sent to IT") {
		t.Fatalf("result %v", shown)
	}
}

// No overrides left and no requests: a plain notification, no dialog.
// Notifications off: nobody is asked.
func TestAsk_Fallbacks(t *testing.T) {
	fa := &fakeAsker{fakeUserNotifier: fakeUserNotifier{readiness: map[string]string{"1000": "supported"}}, choice: "override", reason: "x"}
	fastNotices(t)
	d, _ := overrideDecider(t, overrideBundle(`, "override_daily_limit": 1`))
	d.SetUserNotifier(fa)
	d.overrides.mu.Lock()
	d.overrides.daily["1000|"+d.overrides.now().Format("2006-01-02")] = 1 // used up
	d.overrides.mu.Unlock()
	d.Decide(context.Background(), uidRequest(), true)
	d.notices.wait()
	if len(fa.asked) != 0 || len(fa.all()) != 1 {
		t.Fatalf("asked %v shown %v", fa.asked, fa.all())
	}

	off := &fakeAsker{fakeUserNotifier: fakeUserNotifier{readiness: map[string]string{"1000": "disabled:app"}}}
	d2, sink2, _ := askDecider(t, off, "")
	d2.Decide(context.Background(), uidRequest(), true)
	d2.asking.wg.Wait()
	if len(off.asked) != 0 || sink2.events()[0].UserNotified == nil || *sink2.events()[0].UserNotified {
		t.Fatalf("notifications off: asked %v event %+v", off.asked, sink2.events()[0])
	}
}
