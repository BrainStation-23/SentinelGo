//go:build windows

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterBootWatchdog_Windows(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, markerFileName)
	m := &Marker{WatchdogPath: `C:\SentinelGo\sentinelgo-update-watchdog.exe`}
	var ran []string
	var xmlSeen []byte
	registered := false
	prev := bootRunFn
	bootRunFn = func(name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		switch args[0] {
		case "/Create":
			// The definition exists while schtasks reads it.
			b, err := os.ReadFile(args[4])
			if err != nil {
				t.Errorf("task XML not readable during /Create: %v", err)
			}
			xmlSeen, registered = b, true
		case "/Query":
			if !registered {
				return errors.New("not found")
			}
		case "/Delete":
			registered = false
		}
		return nil
	}
	t.Cleanup(func() { bootRunFn = prev })

	if err := registerBootWatchdog(m, marker); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || !strings.HasPrefix(ran[0], `schtasks /Create /TN SentinelGo\UpdateWatchdog /XML `) || !strings.HasSuffix(ran[0], " /F") {
		t.Fatalf("ran %q", ran)
	}
	if len(xmlSeen) < 2 || xmlSeen[0] != 0xff || xmlSeen[1] != 0xfe {
		t.Error("task XML isn't UTF-16LE")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "update_boot_task.*.xml")); len(left) != 0 {
		t.Errorf("task XML left behind: %v", left)
	}

	ran = nil
	if err := unregisterBootWatchdog(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, "; ") != `schtasks /Query /TN SentinelGo\UpdateWatchdog; schtasks /Delete /TN SentinelGo\UpdateWatchdog /F` {
		t.Errorf("ran %q", ran)
	}
	// Not registered: only the query.
	ran = nil
	if err := unregisterBootWatchdog(); err != nil || len(ran) != 1 {
		t.Errorf("second unregister: %v, ran %q", err, ran)
	}
}
