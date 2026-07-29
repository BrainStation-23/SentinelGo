//go:build darwin

package main

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"

	"sentinelgo/internal/epm/prompt"
)

func init() {
	newPlatformPrompter = func() prompt.Prompter { return prompt.NewDarwinPrompter() }
	newPlatformAutostart = func() autostart { return darwinAutostart{} }
}

// darwinAutostart writes a per-user LaunchAgent plist — the standard macOS
// mechanism for starting a user-space helper at login, loaded automatically
// by launchd from ~/Library/LaunchAgents on every login without any
// separate `launchctl load` step required (launchd watches that directory).
type darwinAutostart struct{}

const launchAgentLabel = "com.sentinelgo.epm.session"

func (darwinAutostart) Install(exePath string) error {
	dir, err := launchAgentsDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// #nosec G306 - a LaunchAgent plist must be world-readable like every
	// other file in ~/Library/LaunchAgents; it contains no secrets.
	return os.WriteFile(launchAgentPath(dir), []byte(buildLaunchAgentPlist(exePath)), 0o644)
}

func (darwinAutostart) Uninstall() error {
	dir, err := launchAgentsDir()
	if err != nil {
		return err
	}
	err = os.Remove(launchAgentPath(dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func launchAgentsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

func launchAgentPath(dir string) string {
	return filepath.Join(dir, launchAgentLabel+".plist")
}

// buildLaunchAgentPlist is split out from Install for testability without
// touching the real filesystem. exePath is XML-escaped since it becomes
// the content of a <string> element.
func buildLaunchAgentPlist(exePath string) string {
	escaped := xmlEscape(exePath)
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n" +
		`<plist version="1.0">` + "\n" +
		`<dict>` + "\n" +
		`	<key>Label</key>` + "\n" +
		`	<string>` + launchAgentLabel + `</string>` + "\n" +
		`	<key>ProgramArguments</key>` + "\n" +
		`	<array>` + "\n" +
		`		<string>` + escaped + `</string>` + "\n" +
		`		<string>-session</string>` + "\n" +
		`	</array>` + "\n" +
		`	<key>RunAtLoad</key>` + "\n" +
		`	<true/>` + "\n" +
		`	<key>KeepAlive</key>` + "\n" +
		`	<true/>` + "\n" +
		`</dict>` + "\n" +
		`</plist>` + "\n"
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
