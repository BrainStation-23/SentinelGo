//go:build !windows && !darwin && !linux

package notify

// Readiness can't be read on this platform.
func Readiness() (state, detail string) { return ReadyUnknown, "not supported on this platform" }
