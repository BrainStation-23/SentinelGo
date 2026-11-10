//go:build !linux && !windows && !darwin

package scanworker

// Serve is `sentinelgo dlp-scan`; workers run on Linux, Windows and macOS.
func Serve() error { return ErrUnsupported }

// RemoveScanAccount has nothing to remove here.
func RemoveScanAccount() error { return nil }
