package clipboard

import (
	"context"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/policy"
)

// stub is the clipboard channel on a platform without a watcher. It reports
// itself unsupported so the device's status says so instead of silently
// enforcing nothing.
type stub struct{}

// New returns the clipboard channel for this platform.
func New() channel.Channel { return stub{} }

func (stub) Name() string { return Name }

func (stub) Supported() channel.Capability { return channel.Unsupported("not_implemented") }

func (stub) Run(context.Context, *policy.Compiled, channel.EventSink) error {
	return channel.ErrUnsupported
}
