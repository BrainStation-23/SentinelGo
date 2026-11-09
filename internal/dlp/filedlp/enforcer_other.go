//go:build !linux && !windows

package filedlp

// New returns nil: file DLP has no hook on this platform yet (Windows #330,
// macOS #332).
func New(Options) Enforcer { return nil }
