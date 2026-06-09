package updater

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// atomicReplace replaces the running binary with newPath using an atomic rename.
// Not used on Windows (handled via restart batch script).
func atomicReplace(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	dir := filepath.Dir(selfPath)
	tempPath := filepath.Join(dir, ".sentinelgo_update_tmp")

	if err := copyFile(newPath, tempPath); err != nil {
		return fmt.Errorf("copy to temp file failed: %w", err)
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	_ = os.Remove(newPath)

	// #nosec G302 - Executable binaries need 0755 permissions
	if err := os.Chmod(selfPath, 0755); err != nil {
		return fmt.Errorf("set executable permissions failed: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	// #nosec G304 - src and dst are controlled paths for self-update
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	// #nosec G304 - dst is a controlled path for self-update
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()

	_, err = io.Copy(destination, source)
	return err
}

func removeFile(path string) error {
	return os.Remove(path)
}

// createBackup copies the running binary to <self>.backup and returns the path.
func createBackup() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	backupPath := selfPath + ".backup"

	// #nosec G304 - selfPath is a controlled path from os.Executable()
	src, err := os.Open(selfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()

	// #nosec G304 - backupPath is a controlled path
	dst, err := os.Create(backupPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to remove backup file %s: %v", backupPath, removeErr)
		}
		return "", err
	}

	if info, err := os.Stat(selfPath); err == nil {
		if err := os.Chmod(backupPath, info.Mode()); err != nil {
			log.Printf("Warning: failed to set permissions on backup: %v", err)
		}
	}

	return backupPath, nil
}

// rollbackFromBackup restores the binary from backupPath using an atomic rename.
func rollbackFromBackup(backupPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("Cannot perform in-process rollback on Windows (file locked).\n")
		fmt.Printf("Backup preserved at: %s\n", backupPath)
		fmt.Printf("To manually restore: copy %s %s\n", backupPath, selfPath)
		return fmt.Errorf("in-process rollback not supported on Windows")
	}

	tempPath := selfPath + ".rollback"
	if err := copyFile(backupPath, tempPath); err != nil {
		return err
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	fmt.Printf("Successfully rolled back from backup: %s\n", backupPath)
	return nil
}

// restart replaces the binary and starts the new version.
func restart(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "darwin" {
		return restartDarwin(newPath, selfPath)
	}

	if runtime.GOOS != "windows" {
		if err := os.Rename(newPath, selfPath); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		// #nosec G204 - selfPath is a controlled path for self-update
		cmd := exec.Command(selfPath)
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
		return nil
	}

	// Windows: use batch script to replace after exit
	bat := selfPath + ".bat"
	script := fmt.Sprintf(`@echo off

timeout /t 2 /nobreak >nul
move /Y "%s" "%s"
"%s"
del "%s"`, newPath, selfPath, selfPath, bat)
	// #nosec G306 - Windows batch scripts need to be readable by the system
	if err := os.WriteFile(bat, []byte(script), 0644); err != nil {
		return err
	}
	// #nosec G204 - bat is a controlled path for self-update
	cmd := exec.Command(bat)
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

func restartDarwin(newPath, selfPath string) error {
	if err := stopLaunchdService(); err != nil {
		fmt.Printf("Warning: Failed to stop launchd service: %v\n", err)
	}

	time.Sleep(3 * time.Second)

	if err := os.Rename(newPath, selfPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	if _, err := os.Stat(selfPath); os.IsNotExist(err) {
		return fmt.Errorf("new binary not found after replacement: %w", err)
	}

	fmt.Printf("Successfully updated to version %s\n", extractVersionFromPath(newPath))

	time.Sleep(2 * time.Second)

	if err := startLaunchdService(); err != nil {
		fmt.Printf("Warning: Failed to start launchd service: %v\n", err)
		fmt.Println("Falling back to direct execution...")
		// #nosec G204 - selfPath is a controlled path for self-update
		cmd := exec.Command(selfPath, "-run")
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start fallback execution: %w", err)
		}
		fmt.Println("Started SentinelGo in direct execution mode")
		os.Exit(0)
	}

	time.Sleep(3 * time.Second)
	fmt.Println("Verifying only new version is running...")

	finalCheck, _ := findOldProcesses()
	if len(finalCheck) > 0 {
		fmt.Printf("Warning: Found %d old process(es) still running after update:\n", len(finalCheck))
		for _, proc := range finalCheck {
			fmt.Printf("  PID: %d, Version: %s\n", proc.PID, proc.Version)
		}
		fmt.Println("Force stopping remaining old processes...")
		forceKillProcesses(finalCheck)
		time.Sleep(1 * time.Second)
	} else {
		fmt.Println("Success: Only new version is running")
	}

	return nil
}

func stopLaunchdService() error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	cmd := exec.Command("launchctl", "list", "com.sentinelgo.agent")
	if err := cmd.Run(); err != nil {
		return nil // not running
	}

	fmt.Println("Stopping launchd service...")
	cmd = exec.Command("launchctl", "unload", "-w", "/Library/LaunchDaemons/com.sentinelgo.agent.plist")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to unload launchd service: %v\n", err)
	}

	return nil
}

func startLaunchdService() error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	fmt.Println("Starting launchd service...")

	plistPath := "/Library/LaunchDaemons/com.sentinelgo.agent.plist"
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		fmt.Printf("Launchd plist not found at %s\n", plistPath)
		return fmt.Errorf("launchd plist file not found - service may not be installed")
	}

	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to load launchd service: %v\nOutput: %s\n", err, string(output))
		return fmt.Errorf("failed to load launchd service: %w", err)
	}

	time.Sleep(500 * time.Millisecond)

	cmd = exec.Command("launchctl", "start", "com.sentinelgo.agent")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to start launchd service: %v\nOutput: %s\n", err, string(output))
		return fmt.Errorf("failed to start launchd service: %w", err)
	}

	time.Sleep(1 * time.Second)
	cmd = exec.Command("launchctl", "list", "com.sentinelgo.agent")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Could not verify launchd service status: %v\n", err)
	} else if strings.Contains(string(output), "com.sentinelgo.agent") {
		fmt.Println("Launchd service started successfully")
	} else {
		fmt.Printf("Warning: Launchd service may not be running properly. Output: %s\n", string(output))
	}

	return nil
}

// forceKillProcesses sends SIGKILL/taskkill to all listed processes.
func forceKillProcesses(processes []ProcessInfo) {
	for _, proc := range processes {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			// #nosec G204 - taskkill is a system command with controlled arguments
			cmd = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID))
		case "linux", "darwin":
			// #nosec G204 - kill is a system command with controlled arguments
			cmd = exec.Command("kill", "-KILL", strconv.Itoa(proc.PID))
		}
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: failed to kill process %d: %v\n", proc.PID, err)
		}
	}
}
