package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"sentinelgo/internal/procinfo"
)

// handleStop stops all running SentinelGo processes.
func handleStop() {
	if err := stopSentinelGoProcesses(); err != nil {
		fmt.Printf("Error stopping processes: %v\n", err)
	}
}

// handleStatus shows running processes, versions, and (on macOS) launchd status.
func handleStatus() {
	if runtime.GOOS == "darwin" {
		if err := checkLaunchdService(); err != nil {
			fmt.Printf("Error checking launchd service: %v\n", err)
		}
	}
	if err := showSentinelGoStatus(); err != nil {
		fmt.Printf("Error showing status: %v\n", err)
	}
	fmt.Printf("Config checkpoint path: %s\n", getCheckpointPath())
}

func stopSentinelGoProcesses() error {
	if runtime.GOOS == "linux" {
		if err := exec.Command("systemctl", "stop", "sentinelgo").Run(); err != nil {
			log.Printf("Warning: failed to stop systemd service: %v", err)
		}
		if err := exec.Command("systemctl", "disable", "sentinelgo").Run(); err != nil {
			log.Printf("Warning: failed to disable systemd service: %v", err)
		}
	}

	if runtime.GOOS == "darwin" {
		if err := exec.Command("launchctl", "unload", "-w", "/Library/LaunchDaemons/com.sentinelgo.agent.plist").Run(); err != nil {
			log.Printf("Warning: failed to unload launchd service: %v", err)
		}
	}

	processes, err := procinfo.FindProcesses()
	if err != nil {
		return err
	}

	if len(processes) == 0 {
		fmt.Println("No running SentinelGo processes found")
		return nil
	}

	fmt.Printf("Found %d SentinelGo process(es):\n", len(processes))
	for _, proc := range processes {
		fmt.Printf("  PID: %d, Version: %s, Status: %s\n", proc.PID, proc.Version, proc.Status)
	}

	fmt.Println("\nStopping processes...")
	for _, proc := range processes {
		switch runtime.GOOS {
		case "windows":
			// #nosec G204 - taskkill is a system command with controlled arguments
			if err := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID)).Run(); err != nil {
				fmt.Printf("Failed to stop PID %d: %v\n", proc.PID, err)
			} else {
				fmt.Printf("Stopped PID %d\n", proc.PID)
			}
		case "linux", "darwin":
			// #nosec G204 - kill is a system command with controlled arguments
			// Send SIGTERM first; escalate to SIGKILL only if the process survives.
			if err := exec.Command("kill", strconv.Itoa(proc.PID)).Run(); err != nil {
				fmt.Printf("Failed to send SIGTERM to PID %d: %v\n", proc.PID, err)
			} else {
				fmt.Printf("Sent SIGTERM to PID %d\n", proc.PID)
			}
		}
	}

	// Give processes a moment to exit after SIGTERM before force-killing.
	if runtime.GOOS != "windows" {
		time.Sleep(2 * time.Second)
	}

	for i := 0; i < 3; i++ {
		processes, _ = procinfo.FindProcesses()
		if len(processes) == 0 {
			break
		}
		fmt.Printf("Retry %d: %d processes still running, force-killing...\n", i+1, len(processes))
		for _, proc := range processes {
			switch runtime.GOOS {
			case "windows":
				// #nosec G204
				_ = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID)).Run()
			case "linux", "darwin":
				// #nosec G204
				_ = exec.Command("kill", "-9", strconv.Itoa(proc.PID)).Run()
			}
		}
	}

	processes, _ = procinfo.FindProcesses()
	if len(processes) > 0 {
		fmt.Printf("Warning: %d processes could not be stopped (may require elevated privileges)\n", len(processes))
	} else {
		fmt.Println("All SentinelGo processes stopped")
	}

	return nil
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
