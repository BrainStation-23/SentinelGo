//go:build !linux && !windows && !darwin

package filedlp

// New returns nil: file DLP has no hook on this platform.
func New(Options) Enforcer { return nil }
