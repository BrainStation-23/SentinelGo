//go:build !windows && !linux && !darwin

package session

// AcquireHelperLock always succeeds where there is no session helper.
func AcquireHelperLock() (release func(), ok bool, err error) { return func() {}, true, nil }
