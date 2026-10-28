// Package channel defines the interface every DLP channel implements. The
// clipboard is the first; USB/removable media, file, print and screenshot
// channels slot in the same way and reuse detect, events and policy.
//
// Channels run inside the per-user session helper (`sentinelgo dlp-session`),
// never in the service, because the content they watch belongs to the user's
// interactive session.
package channel

import (
	"context"
	"errors"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// ErrUnsupported is returned by Run on a platform or session where the channel
// can't work. Capability says why.
var ErrUnsupported = errors.New("dlp channel not supported here")

// Capability says whether a channel can run on this device and session.
type Capability struct {
	Supported bool
	Reason    string // why not, when !Supported, e.g. "wayland_no_data_control"
}

// Supported is the capability of a channel that can run.
func Supported() Capability { return Capability{Supported: true} }

// Unsupported is the capability of a channel that can't run, for reason.
func Unsupported(reason string) Capability { return Capability{Reason: reason} }

// String is the form reported to the backend: "supported" or
// "unsupported:<reason>".
func (c Capability) String() string {
	if c.Supported {
		return "supported"
	}
	return "unsupported:" + c.Reason
}

// EventSink receives the events a channel records.
type EventSink interface {
	Emit(ev events.Event)
}

// Channel watches one way data can leave the device and enforces the policy
// on it.
type Channel interface {
	// Name is the channel's name in bundles and events, e.g. "clipboard".
	Name() string
	// Supported reports whether the channel can run here.
	Supported() Capability
	// Run enforces p until ctx is cancelled. It returns ErrUnsupported when the
	// channel can't run here.
	Run(ctx context.Context, p *policy.Compiled, sink EventSink) error
}
