//go:build darwin

package notify

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

// Bundle IDs the notifications are posted under: terminal-notifier's when it
// is installed, else osascript's (Script Editor).
const (
	terminalNotifierBundle = "fr.julienxx.oss.terminal-notifier"
	osascriptBundle        = "com.apple.ScriptEditor2"
)

// plistJSON converts a property list file to JSON with plutil.
func plistJSON(path string) []byte {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", path).Output() // #nosec G204 -- fixed tool; the path is the user's own preferences file
	if err != nil {
		return nil
	}
	return out
}

// Readiness reads the user's notification preferences for the app our
// notifications come from, and a managed (MDM) setting for it.
func Readiness() (state, detail string) {
	bundle := osascriptBundle
	if findTerminalNotifier() != "" {
		bundle = terminalNotifierBundle
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ReadyUnknown, "no home directory"
	}
	var managed *bool
	if u, err := user.Current(); err == nil {
		for _, p := range []string{
			filepath.Join("/Library/Managed Preferences", u.Username, "com.apple.notificationsettings.plist"),
			"/Library/Managed Preferences/com.apple.notificationsettings.plist",
		} {
			if js := plistJSON(p); js != nil {
				if managed = managedNotificationEnabled(js, bundle); managed != nil {
					break
				}
			}
		}
	}
	return darwinReadiness(plistJSON(filepath.Join(home, "Library/Preferences/com.apple.ncprefs.plist")), bundle, managed)
}
