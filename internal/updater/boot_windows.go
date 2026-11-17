//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"sentinelgo/internal/binpath"
)

// bootRunFn runs a system tool; swapped in tests.
var bootRunFn = func(name string, args ...string) error {
	// #nosec G204 -- fixed tools resolved to absolute paths, fixed arguments
	cmd := exec.Command(binpath.Resolve(name), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, out)
	}
	return nil
}

// registerBootWatchdog creates (or replaces) the scheduled task from XML,
// written next to the marker (a SYSTEM/Administrators-only directory) and
// deleted afterwards.
func registerBootWatchdog(m *Marker, markerPath string) error {
	x, err := scheduledTaskXML(m, markerPath)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(markerPath), "update_boot_task.*.xml")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.Write(x)
	if cerr := f.Close(); werr != nil || cerr != nil {
		return fmt.Errorf("write the task definition: %v %v", werr, cerr)
	}
	return bootRunFn("schtasks", "/Create", "/TN", bootTaskName, "/XML", tmp, "/F")
}

// unregisterBootWatchdog deletes the task; nothing to do when it isn't there.
func unregisterBootWatchdog() error {
	if err := bootRunFn("schtasks", "/Query", "/TN", bootTaskName); err != nil {
		return nil // not registered
	}
	return bootRunFn("schtasks", "/Delete", "/TN", bootTaskName, "/F")
}
