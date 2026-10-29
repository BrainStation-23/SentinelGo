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
	notifyBlocked(d)
	if len(testNotifier.msgs) != before+1 || !strings.Contains(testNotifier.msgs[before], "credit card") {
		t.Errorf("notifyBlocked didn't notify: %v", testNotifier.msgs)
	}
}

// A block that couldn't be applied (events marked monitored) doesn't notify.
func TestNotifyBlocked_OnlyWhenReallyBlocked(t *testing.T) {
	d := Decide(compile(t, blockCards), "4111111111111111", events.SourceApp{}, now)
	markMonitored(d.Events)
	before := len(testNotifier.msgs)
	notifyBlocked(d)
	if len(testNotifier.msgs) != before {
		t.Error("notified although nothing was blocked")
	}
}
