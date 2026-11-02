// Package clipboard is the clipboard DLP channel: it watches the user's
// clipboard, scans copied text against the policy and records (monitor),
// records and tells the user (warn) or replaces (block) content that matches. Each OS has its own watcher in
// clipboard_<os>.go; platforms without one use clipboard_stub.go.
//
// Clipboard content is never logged or stored.
package clipboard

import (
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/notify"
	"sentinelgo/internal/dlp/policy"
)

// Name is the channel's name in bundles and events.
const Name = policy.ChannelClipboard

// notifier shows the block and warn notifications (rate-limited,
// asynchronous). A var for tests.
var notifier interface{ Notify(title, body string) } = notify.New()

// notifyUser tells the user a copy was blocked or warned about, and only if
// that is what was recorded: a copy that couldn't be replaced is recorded as
// monitored, so it gets no notification. It never waits, and a failure never
// affects enforcement.
func notifyUser(d Decision) {
	if d.Notify == "" {
		return
	}
	want := ""
	switch {
	case d.Block:
		want = events.ActionBlocked
	case d.Warn:
		want = events.ActionWarned
	default:
		return
	}
	for _, ev := range d.Events {
		if ev.Action == want {
			notifier.Notify(notifyTitle, d.Notify)
			return
		}
	}
}
