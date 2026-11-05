package scanworker

// RemoveScanAccount has nothing to remove on Windows: workers run with a
// restricted copy of the service's token, not a separate account.
func RemoveScanAccount() error { return nil }
