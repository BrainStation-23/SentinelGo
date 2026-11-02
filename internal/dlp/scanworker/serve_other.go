//go:build !linux

package scanworker

// Serve is `sentinelgo dlp-scan`; workers only run on Linux so far.
func Serve() error { return ErrUnsupported }

// RemoveScanAccount has nothing to remove here: workers only run on Linux.
func RemoveScanAccount() error { return nil }
