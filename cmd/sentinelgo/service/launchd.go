package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"sentinelgo/internal/binpath"
)

// launchdPlistPath is where the macOS launchd job definition is installed,
// bootstrapped, booted out, and removed.
const launchdPlistPath = "/Library/LaunchDaemons/com.sentinelgo.agent.plist"

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
        <string>--config</string>
        <string>/opt/sentinelgo/.sentinelgo/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/sentinelgo.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/sentinelgo.log</string>
    <key>UserName</key>
    <string>root</string>
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
	if err := os.WriteFile(launchdPlistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}

	fmt.Println("Created launchd plist: /Library/LaunchDaemons/com.sentinelgo.agent.plist")
	return nil
}

func loadLaunchdService() error {
	// launchctl bootstrap is the supported API on macOS 10.15+; launchctl load is deprecated.
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	if err := exec.Command(binpath.Resolve("launchctl"), "bootstrap", "system", launchdPlistPath).Run(); err != nil {
		return fmt.Errorf("load launchd service: %w", err)
	}
	fmt.Println("Loaded launchd service: com.sentinelgo.agent")
	return nil
}

func unloadLaunchdService() error {
	// launchctl bootout is the supported API on macOS 10.15+; launchctl unload is deprecated.
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	if err := exec.Command(binpath.Resolve("launchctl"), "bootout", "system", launchdPlistPath).Run(); err != nil {
		return fmt.Errorf("unload launchd service: %w", err)
	}
	fmt.Println("Unloaded launchd service: com.sentinelgo.agent")
	return nil
}

func removeLaunchdPlist() error {
	if err := os.Remove(launchdPlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist file: %w", err)
	}
	fmt.Println("Removed launchd plist: /Library/LaunchDaemons/com.sentinelgo.agent.plist")
	return nil
}

// CheckLaunchdService prints the launchd status for sentinelgo entries.
// Called by the cli/process.go HandleStatus command.
func CheckLaunchdService() error {
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	cmd := exec.Command(binpath.Resolve("sh"), "-c", "launchctl list | grep sentinelgo")
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
