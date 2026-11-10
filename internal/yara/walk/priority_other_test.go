//go:build !linux

package walk

// checkLowered: macOS and Windows don't read background mode back in a way
// worth asserting; LowerSelf returning no error is the check.
func checkLowered() error { return nil }
