// Package clipboard is the clipboard DLP channel: it watches the user's
// clipboard, scans copied text against the policy and records (monitor) or
// replaces (block) content that matches. Each OS has its own watcher in
// clipboard_<os>.go; platforms without one use clipboard_stub.go.
//
// Clipboard content is never logged or stored.
package clipboard

import "sentinelgo/internal/dlp/policy"

// Name is the channel's name in bundles and events.
const Name = policy.ChannelClipboard
