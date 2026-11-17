//go:build !windows

package updater

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeBootRun records the system tools the real registration runs.
func fakeBootRun(t *testing.T) *[]string {
	t.Helper()
	var ran []string
	prev := bootRunFn
	bootRunFn = func(name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { bootRunFn = prev })
	return &ran
}

func TestRegisterBootWatchdog_Unix(t *testing.T) {
	ran := fakeBootRun(t)
	dir := t.TempDir()
	prevUnit, prevLD := systemdUnitDir, launchdBootDir
	systemdUnitDir, launchdBootDir = dir, dir
	t.Cleanup(func() { systemdUnitDir, launchdBootDir = prevUnit, prevLD })
	m := bootMarker()
	marker := "/opt/sentinelgo/.sentinelgo/update_marker.json"

	err := registerBootWatchdog(m, marker)
	switch runtime.GOOS {
	case "linux":
		if err == errBootUnsupported {
			t.Skip("no systemctl on this machine")
		}
		if err != nil {
			t.Fatal(err)
		}
		b, rerr := os.ReadFile(filepath.Join(dir, bootUnitName))
		if rerr != nil || !strings.Contains(string(b), "--boot") {
			t.Fatalf("unit file: %v %q", rerr, b)
		}
		if strings.Join(*ran, "; ") != "systemctl daemon-reload; systemctl enable "+bootUnitName {
			t.Errorf("ran %q", *ran)
		}
		*ran = nil
		if err := unregisterBootWatchdog(); err != nil {
			t.Fatal(err)
		}
		if _, serr := os.Stat(filepath.Join(dir, bootUnitName)); !os.IsNotExist(serr) {
			t.Error("unit file left behind")
		}
		if strings.Join(*ran, "; ") != "systemctl disable "+bootUnitName+"; systemctl daemon-reload" {
			t.Errorf("ran %q", *ran)
		}
		// Nothing registered: no systemctl at all.
		*ran = nil
		if err := unregisterBootWatchdog(); err != nil || len(*ran) != 0 {
			t.Errorf("second unregister: %v, ran %q", err, *ran)
		}
	case "darwin":
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, bootLabel+".plist")
		if b, rerr := os.ReadFile(path); rerr != nil || !strings.Contains(string(b), "<string>--boot</string>") {
			t.Fatalf("plist: %v %q", rerr, b)
		}
		if len(*ran) != 0 {
			t.Errorf("ran %q; registering only writes the plist", *ran)
		}
		if err := unregisterBootWatchdog(); err != nil {
			t.Fatal(err)
		}
		if _, serr := os.Stat(path); !os.IsNotExist(serr) {
			t.Error("plist left behind")
		}
		if err := unregisterBootWatchdog(); err != nil {
			t.Errorf("second unregister: %v", err)
		}
	default:
		if err != errBootUnsupported {
			t.Errorf("err = %v, want errBootUnsupported", err)
		}
	}
}
