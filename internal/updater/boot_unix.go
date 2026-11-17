//go:build !windows

package updater

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"sentinelgo/internal/binpath"
)

// Where the boot jobs live; variables for tests.
var (
	systemdUnitDir = "/etc/systemd/system"
	launchdBootDir = "/Library/LaunchDaemons"
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

func registerBootWatchdog(m *Marker, markerPath string) error {
	switch runtime.GOOS {
	case "linux":
		if _, ok := binpath.Lookup("systemctl"); !ok {
			return errBootUnsupported
		}
		unit, err := systemdUnit(m, markerPath)
		if err != nil {
			return err
		}
		// #nosec G306 -- systemd unit files are world-readable by convention; root owns the directory
		if err := os.WriteFile(filepath.Join(systemdUnitDir, bootUnitName), []byte(unit), 0o644); err != nil {
			return err
		}
		if err := bootRunFn("systemctl", "daemon-reload"); err != nil {
			return err
		}
		// Enable only: a watchdog is already running, the unit is for the next boot.
		return bootRunFn("systemctl", "enable", bootUnitName)
	case "darwin":
		plist, err := launchdBootPlist(m, markerPath)
		if err != nil {
			return err
		}
		// launchd loads every plist in /Library/LaunchDaemons at boot. It
		// isn't bootstrapped now: a watchdog is already running.
		// #nosec G306 -- launchd requires root-owned, world-readable job files
		return os.WriteFile(filepath.Join(launchdBootDir, bootLabel+".plist"), []byte(plist), 0o644)
	}
	return errBootUnsupported
}

func unregisterBootWatchdog() error {
	switch runtime.GOOS {
	case "linux":
		path := filepath.Join(systemdUnitDir, bootUnitName)
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil // nothing registered: no systemctl calls
		}
		_ = bootRunFn("systemctl", "disable", bootUnitName)
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return bootRunFn("systemctl", "daemon-reload")
	case "darwin":
		// Not booted out: when the boot-started watchdog itself calls this,
		// bootout would kill it. Without the file the job isn't loaded at the
		// next boot; an idle loaded job until then is harmless.
		err := os.Remove(filepath.Join(launchdBootDir, bootLabel+".plist"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return nil
}
