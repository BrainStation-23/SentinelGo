package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/updater"
)

func TestRunUpdateWatchdog_RequiresAbsoluteMarker(t *testing.T) {
	for _, args := range [][]string{nil, {"--marker", "relative.json"}, {"--bogus"}} {
		var stderr bytes.Buffer
		if code := RunUpdateWatchdog(args, &stderr); code != 2 {
			t.Errorf("RunUpdateWatchdog(%q) = %d, want 2", args, code)
		}
	}
}

// With no marker (the update was already confirmed), the watchdog exits at
// once and logs next to the marker.
func TestRunUpdateWatchdog_NoMarkerExits(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	if code := RunUpdateWatchdog([]string{"--marker", filepath.Join(dir, "update_marker.json")}, &stderr); code != 0 {
		t.Fatalf("exit %d (%s), want 0", code, stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, updater.WatchdogLogName))
	if err != nil || !bytes.Contains(b, []byte("no update pending")) {
		t.Errorf("watchdog log = %q, %v", b, err)
	}
}
