//go:build !linux && !darwin && !windows

package walk

// LowerSelf is a no-op where the agent doesn't run.
func LowerSelf() error { return nil }
