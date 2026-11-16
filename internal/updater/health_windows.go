//go:build windows

package updater

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"sentinelgo/internal/binpath"
)

// Process creation flags for a watchdog that outlives the service process.
const (
	detachedProcess        = 0x00000008
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
)

// stopWait is how long installBackup waits for the stopped service to release
// the binary.
const stopWait = 2 * time.Minute

// installBackup stops the service, then copies the backup over the binary,
// retrying until the stopped process releases the file.
func installBackup(m *Marker) error {
	// #nosec G204 -- fixed tool path and service name
	_ = exec.Command(binpath.Resolve("sc.exe"), "stop", windowsServiceName).Run()
	deadline := time.Now().Add(stopWait)
	for {
		err := replaceWithBackup(m)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("binary still locked after %s: %w", stopWait, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// restartService starts the service with the restored binary.
func restartService() error {
	// #nosec G204 -- fixed tool path and service name
	cmd := exec.Command(binpath.Resolve("sc.exe"), "start", windowsServiceName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sc start: %w (%s)", err, out)
	}
	return nil
}

// startService starts the service; sc fails harmlessly (1056) when it is
// already running.
func startService() error { return restartService() }

// spawnWatchdog starts the watchdog detached from the service process (like
// the update script), breaking away from a job object when the service runs
// in one.
func spawnWatchdog(m *Marker, markerPath string) error {
	start := func(flags uint32) error {
		// #nosec G204 -- our own binary copy and marker path
		cmd := exec.Command(m.WatchdogPath, UpdateWatchdogCommand, "--marker", markerPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	base := uint32(detachedProcess | createNewProcessGroup)
	if err := start(base | createBreakawayFromJob); err == nil {
		return nil
	}
	// The job doesn't allow breakaway; without a kill-on-close job the
	// watchdog still survives the service's exit.
	return start(base)
}
