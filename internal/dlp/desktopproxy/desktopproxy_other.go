//go:build !linux

package desktopproxy

// New returns nil: Windows and macOS redirect machine-wide from the
// service (uploadproxy), so helpers there never set a proxy.
func New() *Manager { return nil }
