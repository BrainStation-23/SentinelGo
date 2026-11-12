// Package remoteconfig carries the server's agent settings from RPC replies
// to the code that applies them (#466).
//
// agent_get_tasks and the agent_enqueue_* replies carry an optional "config"
// member (sentinel-ops#902). Each RPC client hands that member to Observe;
// the running service registers the one Handler that applies it. Without a
// handler (CLI commands, tests) Observe does nothing, so a one-shot command
// never rewrites the service's config.
//
// The package has no dependencies so any RPC client can import it.
package remoteconfig

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
)

// Handler applies one raw "config" member. It must be safe for concurrent
// use: replies arrive on many goroutines.
type Handler func(raw json.RawMessage)

var handler atomic.Pointer[Handler]

// SetHandler registers h as the receiver of every observed block, replacing
// any earlier one. nil unregisters.
func SetHandler(h Handler) {
	if h == nil {
		handler.Store(nil)
		return
	}
	handler.Store(&h)
}

// Observe passes raw to the registered handler. An absent or null member
// (an older server) is ignored.
func Observe(raw json.RawMessage) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return
	}
	if h := handler.Load(); h != nil {
		(*h)(raw)
	}
}
