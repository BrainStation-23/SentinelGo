//go:build linux || darwin

package peripherals

import "strings"

// determineDeviceType classifies a device by its name. Returns an empty string
// when the device cannot be categorised — callers should apply their own fallback.
func determineDeviceType(name, nameLower string) string {
	switch {
	case strings.Contains(nameLower, "keyboard"):
		return "Keyboard"
	case strings.Contains(nameLower, "mouse") || strings.Contains(nameLower, "trackpad") || strings.Contains(nameLower, "pointing"):
		return "Mouse or other pointing device"
	case strings.Contains(nameLower, "camera") || strings.Contains(nameLower, "webcam"):
		return "Camera"
	case strings.Contains(nameLower, "microphone"):
		return "Microphone"
	case strings.Contains(nameLower, "speaker"):
		return "Speaker"
	case strings.Contains(nameLower, "headphone"):
		return "Headphones"
	case strings.Contains(nameLower, "touchscreen"):
		return "Touchscreen"
	case strings.Contains(nameLower, "fingerprint"):
		return "Fingerprint Reader"
	case strings.Contains(nameLower, "gamepad") || strings.Contains(nameLower, "controller"):
		return "Game Controller"
	case strings.Contains(nameLower, "storage") || strings.Contains(nameLower, "drive"):
		return "Storage Device"
	}
	return ""
}
