package cli

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	svcsub "sentinelgo/cmd/sentinelgo/service"
	"sentinelgo/internal/binpath"
	"sentinelgo/internal/procinfo"
)

// HandleStop stops all running SentinelGo processes.
func HandleStop() {
	if err := stopSentinelGoProcesses(); err != nil {
		fmt.Printf("Error stopping processes: %v\n", err)
	}
}

// HandleStatus shows running processes, versions, and (on macOS) launchd status.
func HandleStatus() {
	if runtime.GOOS == "darwin" {
		if err := svcsub.CheckLaunchdService(); err != nil {
			fmt.Printf("Error checking launchd service: %v\n", err)
		}
	}
	if err := showSentinelGoStatus(); err != nil {
		fmt.Printf("Error showing status: %v\n", err)
	}
	fmt.Printf("Config checkpoint path: %s\n", getCheckpointPath())
}

func stopSentinelGoProcesses() error {
	stopPlatformService()

	processes, err := procinfo.FindProcesses()
	if err != nil {
		return err
	}

	if len(processes) == 0 {
		fmt.Println("No running SentinelGo processes found")
		return nil
	}

	printProcessList(processes)

	fmt.Println("\nStopping processes...")
	for _, proc := range processes {
		terminateProcessGracefully(proc)
	}

	// Give processes a moment to exit after SIGTERM before force-killing.
	if runtime.GOOS != "windows" {
		time.Sleep(2 * time.Second)
	}

	forceKillRemainingProcesses()
	reportStopOutcome()

	return nil
}

// stopPlatformService stops the OS service wrapper (systemd on Linux, launchd
// on macOS) so it doesn't immediately relaunch the agent after we kill it.
func stopPlatformService() {
	switch runtime.GOOS {
	case "linux":
		stopSystemdService()
	case "darwin":
		stopLaunchdService()
	}
}

func stopSystemdService() {
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	if err := exec.Command(binpath.Resolve("systemctl"), "stop", "sentinelgo").Run(); err != nil {
		log.Printf("Warning: failed to stop systemd service: %v", err)
	}
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	if err := exec.Command(binpath.Resolve("systemctl"), "disable", "sentinelgo").Run(); err != nil {
		log.Printf("Warning: failed to disable systemd service: %v", err)
	}
}

func stopLaunchdService() {
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	if err := exec.Command(binpath.Resolve("launchctl"), "unload", "-w", "/Library/LaunchDaemons/com.sentinelgo.agent.plist").Run(); err != nil {
		log.Printf("Warning: failed to unload launchd service: %v", err)
	}
}

func printProcessList(processes []procinfo.ProcessInfo) {
	fmt.Printf("Found %d SentinelGo process(es):\n", len(processes))
	for _, proc := range processes {
		fmt.Printf("  PID: %d, Version: %s, Status: %s\n", proc.PID, proc.Version, proc.Status)
	}
}

// terminateProcessGracefully asks a single process to exit: taskkill /F on
// Windows (no graceful-stop signal there), SIGTERM on Linux/macOS.
func terminateProcessGracefully(proc procinfo.ProcessInfo) {
	switch runtime.GOOS {
	case "windows":
		// #nosec G204 - taskkill is a system command with controlled arguments
		if err := exec.Command(binpath.Resolve("taskkill"), "/F", "/PID", strconv.Itoa(proc.PID)).Run(); err != nil {
			fmt.Printf("Failed to stop PID %d: %v\n", proc.PID, err)
		} else {
			fmt.Printf("Stopped PID %d\n", proc.PID)
		}
	case "linux", "darwin":
		// #nosec G204 - kill is a system command with controlled arguments
		// Send SIGTERM first; escalate to SIGKILL only if the process survives.
		if err := exec.Command(binpath.Resolve("kill"), strconv.Itoa(proc.PID)).Run(); err != nil {
			fmt.Printf("Failed to send SIGTERM to PID %d: %v\n", proc.PID, err)
		} else {
			fmt.Printf("Sent SIGTERM to PID %d\n", proc.PID)
		}
	}
}

// forceKillProcess kills a single process unconditionally: taskkill /F on
// Windows, SIGKILL on Linux/macOS.
func forceKillProcess(proc procinfo.ProcessInfo) {
	switch runtime.GOOS {
	case "windows":
		// #nosec G204
		_ = exec.Command(binpath.Resolve("taskkill"), "/F", "/PID", strconv.Itoa(proc.PID)).Run()
	case "linux", "darwin":
		// #nosec G204
		_ = exec.Command(binpath.Resolve("kill"), "-9", strconv.Itoa(proc.PID)).Run()
	}
}

// forceKillRemainingProcesses retries up to 3 times, force-killing any
// SentinelGo process that survived the graceful SIGTERM/taskkill above.
func forceKillRemainingProcesses() {
	for i := 0; i < 3; i++ {
		processes, _ := procinfo.FindProcesses()
		if len(processes) == 0 {
			break
		}
		fmt.Printf("Retry %d: %d processes still running, force-killing...\n", i+1, len(processes))
		for _, proc := range processes {
			forceKillProcess(proc)
		}
	}
}

func reportStopOutcome() {
	processes, _ := procinfo.FindProcesses()
	if len(processes) > 0 {
		fmt.Printf("Warning: %d processes could not be stopped (may require elevated privileges)\n", len(processes))
	} else {
		fmt.Println("All SentinelGo processes stopped")
	}
}

func showSentinelGoStatus() error {
	processes, err := procinfo.FindProcesses()
	if err != nil {
		return fmt.Errorf("failed to find processes: %w", err)
	}
	if len(processes) == 0 {
		fmt.Println("No SentinelGo processes are running")
		return nil
	}
	fmt.Printf("Found %d SentinelGo process(es):\n", len(processes))
	for _, proc := range processes {
		status := "unknown"
		if proc.CmdLine != "" {
			status = "running"
		}
		fmt.Printf("  PID: %-8d Version: %-12s Status: %s\n", proc.PID, proc.Version, status)
	}
	return nil
}

func getCheckpointPath() string {
	return procinfo.GetCheckpointPath()
}
