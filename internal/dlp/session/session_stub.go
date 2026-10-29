//go:build !windows && !linux && !darwin

package session

import (
	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// New returns the session supervisor for this platform. Helper events go to
// sink. macOS and Linux get launchers in #265 / #267.
func New(sink channel.EventSink) Supervisor {
	return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
}

// CleanupHelpers has nothing to remove on this platform.
func CleanupHelpers() error { return nil }
