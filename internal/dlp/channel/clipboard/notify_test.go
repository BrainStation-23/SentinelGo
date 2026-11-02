package clipboard

import (
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/dlp/events"
)

// fakeNotifier records notifications instead of showing them.
type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeNotifier) Notify(_, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, body)
}

var testNotifier = &fakeNotifier{}

func init() { notifier = testNotifier } // no real toasts from tests

func TestDecide_NotifyMessage(t *testing.T) {
	p := compile(t, blockCards)
	d := Decide(p, "4111111111111111", events.SourceApp{}, now)
	if d.Notify != "SentinelOps blocked sensitive data on your clipboard: credit card" {
		t.Errorf("default notify = %q", d.Notify)
	}
	p.Modules.Clipboard.NotifyMessage = "Careful: {{detector}} removed"
	if d := Decide(p, "4111111111111111", events.SourceApp{}, now); d.Notify != "Careful: credit card removed" {
		t.Errorf("custom notify = %q", d.Notify)
	}
	if d := Decide(compile(t, monitorFalcon), "falcon", events.SourceApp{}, now); d.Notify != "" {
		t.Error("monitor-only copy would notify")
	}

	before := len(testNotifier.msgs)
	notifyUser(d)
	if len(testNotifier.msgs) != before+1 || !strings.Contains(testNotifier.msgs[before], "credit card") {
		t.Errorf("notifyUser didn't notify: %v", testNotifier.msgs)
	}
}

// A warned copy notifies with the warn message; a monitor-only one doesn't.
func TestNotifyUser_Warn(t *testing.T) {
	before := len(testNotifier.msgs)
	notifyUser(Decide(compile(t, warnEmails), "jane@example.com", events.SourceApp{}, now))
	if len(testNotifier.msgs) != before+1 || !strings.Contains(testNotifier.msgs[before], "allowed and logged") {
		t.Errorf("warn not notified: %v", testNotifier.msgs[before:])
	}
	notifyUser(Decide(compile(t, monitorFalcon), "falcon", events.SourceApp{}, now))
	if len(testNotifier.msgs) != before+1 {
		t.Error("monitor-only copy notified")
	}
}

// A block that couldn't be applied (events marked monitored) doesn't notify.
func TestNotifyUser_OnlyWhenReallyBlocked(t *testing.T) {
	d := Decide(compile(t, blockCards), "4111111111111111", events.SourceApp{}, now)
	markMonitored(d.Events)
	before := len(testNotifier.msgs)
	notifyUser(d)
	if len(testNotifier.msgs) != before {
		t.Error("notified although nothing was blocked")
	}
}
