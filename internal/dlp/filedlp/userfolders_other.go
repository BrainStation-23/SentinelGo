//go:build !windows

package filedlp

import "sentinelgo/internal/dlp/channel"

// UserFolderChannels are the helper's file channels: none here (on Linux and
// macOS the service sees every mount itself).
func UserFolderChannels() []channel.Channel { return nil }
