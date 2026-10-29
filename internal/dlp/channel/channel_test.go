package channel_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/channel/clipboard"
	"sentinelgo/internal/dlp/policy"
)

func TestCapabilityString(t *testing.T) {
	if got := channel.Supported().String(); got != "supported" {
		t.Errorf("Supported().String() = %q", got)
	}
	if got := channel.Unsupported("wayland_no_data_control").String(); got != "unsupported:wayland_no_data_control" {
		t.Errorf("Unsupported().String() = %q", got)
	}
}

// Where the clipboard channel has no watcher it must say so rather than run
// and enforce nothing.
func TestClipboardStubReportsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has a watcher (clipboard_windows_test.go)")
	}
	ch := clipboard.New()
	if ch.Name() != policy.ChannelClipboard {
		t.Errorf("Name = %q, want %q", ch.Name(), policy.ChannelClipboard)
	}
	if ch.Supported().Supported {
		t.Error("stub clipboard channel reports supported")
	}
	err := ch.Run(context.Background(), &policy.Compiled{}, nil)
	if !errors.Is(err, channel.ErrUnsupported) {
		t.Errorf("Run = %v, want ErrUnsupported", err)
	}
}
