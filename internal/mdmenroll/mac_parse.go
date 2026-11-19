package mdmenroll

import (
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// activeIdle is how long without keyboard or mouse input a user still counts
// as at the Mac.
const activeIdle = 2 * time.Minute

// consoleLocked reads `ioreg -n Root -d1 -a`: whether the screen of the user
// with uid is locked. The IOConsoleUsers entry carries
// CGSSessionScreenIsLocked only while that session's screen is locked;
// IOConsoleLocked covers the console as a whole. ok is false when the output
// can't be read or has no entry for uid.
func consoleLocked(out, uid string) (locked, ok bool) {
	v, ok := shared.PlistFromOutput(out)
	if !ok {
		return false, false
	}
	root, _ := v.(map[string]any)
	if root == nil {
		return false, false
	}
	whole, _ := shared.PlistBool(root["IOConsoleLocked"])
	users, _ := root["IOConsoleUsers"].([]any)
	for _, u := range users {
		d, _ := u.(map[string]any)
		if d == nil {
			continue
		}
		id, ok := shared.PlistInt(d["kCGSSessionUserIDKey"])
		if !ok || strconv.Itoa(id) != uid {
			continue
		}
		if on, ok := shared.PlistBool(d["kCGSSessionOnConsoleKey"]); ok && !on {
			continue // a fast-user-switched session in the background
		}
		screen, _ := shared.PlistBool(d["CGSSessionScreenIsLocked"])
		return whole || screen, true
	}
	return false, false
}

// macUserActive decides from the two ioreg outputs ("" when a read failed)
// whether the user with uid is at the Mac: their screen isn't locked and
// there was input in the last activeIdle. What the output can't tell counts
// as active, so a Mac whose ioreg changes still gets the profile.
func macUserActive(rootOut, hidOut, uid string) bool {
	if locked, ok := consoleLocked(rootOut, uid); ok && locked {
		return false
	}
	if idle, ok := hidIdle(hidOut); ok && idle >= activeIdle {
		return false
	}
	return true
}

// hidIdle reads `ioreg -r -c IOHIDSystem -d1 -a`: the time since the last
// keyboard, mouse or trackpad input (HIDIdleTime, in nanoseconds).
func hidIdle(out string) (time.Duration, bool) {
	v, ok := shared.PlistFromOutput(out)
	if !ok {
		return 0, false
	}
	entries, _ := v.([]any)
	if d, isDict := v.(map[string]any); isDict {
		entries = []any{d}
	}
	for _, e := range entries {
		d, _ := e.(map[string]any)
		ns, ok := shared.PlistNumber(d["HIDIdleTime"])
		if ok && ns >= 0 && ns < float64(1<<62) {
			return time.Duration(ns), true
		}
	}
	return 0, false
}

// macMajor is the major version in kern.osproductversion ("15.1" -> 15); 0
// when it can't be read.
func macMajor(version string) int {
	s, _, _ := strings.Cut(strings.TrimSpace(version), ".")
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Where the user installs a downloaded profile.
const (
	// deviceManagementPane is System Settings > General > Device Management
	// (macOS 13 and later).
	deviceManagementPane = "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
	// profilesPrefPane is System Preferences > Profiles (macOS 12 and
	// earlier).
	profilesPrefPane = "/System/Library/PreferencePanes/Profiles.prefPane"
)

// installPane is what `open` takes to show where a downloaded profile is
// installed on macOS major (0 when unknown: the current System Settings).
func installPane(major int) string {
	if major > 0 && major < 13 {
		return profilesPrefPane
	}
	return deviceManagementPane
}
