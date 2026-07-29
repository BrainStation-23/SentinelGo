//go:build darwin

package procmon

import "testing"

func TestNew_ReturnsNonNilMonitor(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestGopsutilSnapshot_DoesNotError is a live smoke test: gopsutil's
// process enumeration touches real kernel state (sysctl kern.proc.all),
// so the only thing worth asserting portably is that it succeeds and
// returns at least the current process — not specific field values, which
// are host-dependent. Skipped under -short since it is a live OS call, the
// same convention used by internal/epm/devicectx's equivalent smoke test.
func TestGopsutilSnapshot_DoesNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("live OS process enumeration; skipped under -short")
	}
	snap, err := gopsutilSnapshot()
	if err != nil {
		t.Fatalf("gopsutilSnapshot() error = %v", err)
	}
	if len(snap) == 0 {
		t.Error("gopsutilSnapshot() returned an empty snapshot on a running system")
	}
}
