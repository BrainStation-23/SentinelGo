// Package clipboard is the clipboard DLP channel: it watches the user's
// clipboard, scans copied text against the policy and records (monitor) or
// replaces (block) content that matches. Each OS has its own watcher in
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

// notifier shows the block notification (rate-limited, asynchronous). A var
// for tests.
var notifier interface{ Notify(title, body string) } = notify.New()

// notifyBlocked tells the user a copy was blocked, and only if it really was
// (a copy that couldn't be replaced is recorded as monitored). It never
// waits, and a failure never affects enforcement.
func notifyBlocked(d Decision) {
	if !d.Block || d.Notify == "" {
		return
	}
	for _, ev := range d.Events {
		if ev.Action == events.ActionBlocked {
			notifier.Notify(notifyTitle, d.Notify)
			return
		}
	}
}
