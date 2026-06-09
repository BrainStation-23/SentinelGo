package osinfo_test

import (
	"sync"
	"testing"

	"sentinelgo/internal/osinfo"
	"sentinelgo/internal/osinfo/shared"
)

var (
	collectOnce sync.Once
	collected   *shared.SystemInfo
)

// collectForTest returns a memoized osinfo.Collect() result. The real collection
// shells out to OS tools (WMI, `ps`, etc.) and is slow, so it is skipped in
// -short mode and executed at most once per package run rather than once per
// test. Tests that assert on collected fields should use this instead of calling
// osinfo.Collect() directly.
func collectForTest(t *testing.T) *shared.SystemInfo {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real osinfo.Collect() (slow OS shell-outs) in -short mode")
	}
	collectOnce.Do(func() { collected = osinfo.Collect() })
	return collected
}
