//go:build !windows

package updater

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"sentinelgo/internal/binpath"
)

// Service names the installers register (install.sh, cmd/sentinelgo/service).
const (
	linuxServiceName = "sentinelgo"
	launchdLabel     = "com.sentinelgo.agent"
)

// installBackup replaces the binary with the backup. The running file can be
// replaced in place; on macOS the restored binary is re-registered with
// Gatekeeper like after an update.
func installBackup(m *Marker) error {
	if err := replaceWithBackup(m); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		recodesignForGatekeeper(m.ExePath)
	}
	return nil
}

// restartService restarts the agent's service so the restored binary runs.
func restartService() error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// #nosec G204 -- fixed tool path and label
		cmd = exec.Command(binpath.Resolve("launchctl"), "kickstart", "-k", "system/"+launchdLabel)
	} else {
		// #nosec G204 -- fixed tool path and unit name
		cmd = exec.Command(binpath.Resolve("systemctl"), "restart", linuxServiceName)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w (%s)", cmd.Args[0], err, out)
	}
	return nil
}

// startService starts the agent's service unless it is running already
// (launchctl kickstart without -k and systemctl start leave a running
// service alone).
func startService() error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// #nosec G204 -- fixed tool path and label
		cmd = exec.Command(binpath.Resolve("launchctl"), "kickstart", "system/"+launchdLabel)
	} else {
		// #nosec G204 -- fixed tool path and unit name
		cmd = exec.Command(binpath.Resolve("systemctl"), "start", linuxServiceName)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w (%s)", cmd.Args[0], err, out)
	}
	return nil
}

// spawnWatchdog starts the watchdog so it outlives the agent's restart. On
// Linux it runs as a transient systemd unit: systemd kills every process in
// the agent's own cgroup when the agent exits. Elsewhere (macOS, or Linux
// without systemd-run) it starts in its own session, outside the process
// group launchd kills with the job.
func spawnWatchdog(m *Marker, markerPath string) error {
	if runtime.GOOS == "linux" {
		if run, ok := binpath.Lookup("systemd-run"); ok && run != "systemd-run" {
			unit := "sentinelgo-update-watchdog-" + strconv.FormatInt(time.Now().Unix(), 10)
			// #nosec G204 -- fixed tool, our own binary copy and marker path
			cmd := exec.Command(run, "--unit="+unit, "--collect", "--quiet", "--",
				m.WatchdogPath, UpdateWatchdogCommand, "--marker", markerPath)
			if out, err := cmd.CombinedOutput(); err == nil {
				return nil
			} else {
				return fmt.Errorf("systemd-run: %w (%s)", err, out)
			}
		}
	}
	// #nosec G204 -- our own binary copy and marker path
	cmd := exec.Command(m.WatchdogPath, UpdateWatchdogCommand, "--marker", markerPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
