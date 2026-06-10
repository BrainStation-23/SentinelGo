package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func createLaunchdPlist() error {
	version := agentVersion
	if version == "" {
		version = "unknown"
	}

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.sentinelgo.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/sentinelgo/sentinelgo</string>
    <string>-run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/sentinelgo.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/sentinelgo.err</string>
  <key>WorkingDirectory</key>
  <string>/opt/sentinelgo</string>
  <key>Comment</key>
  <string>SentinelGo Agent v%s - Cross-platform system monitoring</string>
</dict>
</plist>`, version)

	// #nosec G301 - /Library/LaunchDaemons is a system directory with standard permissions
	if err := os.MkdirAll("/Library/LaunchDaemons", 0755); err != nil {
		return fmt.Errorf("create LaunchDaemons directory: %w", err)
	}

	// #nosec G306 - LaunchDaemon plist files need to be readable by launchd
	if err := os.WriteFile("/Library/LaunchDaemons/com.sentinelgo.agent.plist", []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}

	fmt.Println("Created launchd plist: /Library/LaunchDaemons/com.sentinelgo.agent.plist")
	return nil
}

func loadLaunchdService() error {
	if err := exec.Command("launchctl", "load", "-w", "/Library/LaunchDaemons/com.sentinelgo.agent.plist").Run(); err != nil {
		return fmt.Errorf("load launchd service: %w", err)
	}
	fmt.Println("Loaded launchd service: com.sentinelgo.agent")
	return nil
}

func unloadLaunchdService() error {
	if err := exec.Command("launchctl", "unload", "-w", "/Library/LaunchDaemons/com.sentinelgo.agent.plist").Run(); err != nil {
		return fmt.Errorf("unload launchd service: %w", err)
	}
	fmt.Println("Unloaded launchd service: com.sentinelgo.agent")
	return nil
}

func removeLaunchdPlist() error {
	if err := os.Remove("/Library/LaunchDaemons/com.sentinelgo.agent.plist"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist file: %w", err)
	}
	fmt.Println("Removed launchd plist: /Library/LaunchDaemons/com.sentinelgo.agent.plist")
	return nil
}

// CheckLaunchdService prints the launchd status for sentinelgo entries.
// Called by the cli/process.go HandleStatus command.
func CheckLaunchdService() error {
	cmd := exec.Command("sh", "-c", "launchctl list | grep sentinelgo")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to check launchd service: %v\n", err)
		return nil
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		fmt.Println("No SentinelGo services found in launchctl")
	} else {
		fmt.Printf("Launchd service status:\n%s\n", string(output))
	}
	return nil
}
