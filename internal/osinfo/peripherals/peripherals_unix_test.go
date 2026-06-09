//go:build linux || darwin

package peripherals

import "testing"

func TestDetermineDeviceType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Known categories
		{"keyboard", "USB Keyboard", "Keyboard"},
		{"KEYBOARD uppercase", "LOGITECH KEYBOARD", "Keyboard"},
		{"mouse", "Logitech USB Mouse", "Mouse or other pointing device"},
		{"trackpad", "Apple Internal Trackpad", "Mouse or other pointing device"},
		{"pointing device", "USB Pointing Device", "Mouse or other pointing device"},
		{"webcam", "HD Webcam C920", "Camera"},
		{"camera", "FaceTime HD Camera", "Camera"},
		{"microphone", "USB Microphone", "Microphone"},
		{"speaker", "USB Speaker", "Speaker"},
		{"headphone", "Bose QuietComfort Headphones", "Headphones"},
		{"touchscreen", "Touchscreen Display", "Touchscreen"},
		{"fingerprint", "Fingerprint Reader", "Fingerprint Reader"},
		{"gamepad", "Xbox Gamepad", "Game Controller"},
		{"controller", "DualSense Controller", "Game Controller"},
		{"storage drive", "USB Storage Drive", "Storage Device"},
		{"storage", "USB Mass Storage", "Storage Device"},

		// Unknown devices should return empty — NOT the device name
		{"unknown returns empty", "Logitech USB Receiver", ""},
		{"hub returns empty", "USB 2.0 Hub", ""},
		{"empty string", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := determineDeviceType(tc.input, lc(tc.input))
			if got != tc.want {
				t.Errorf("determineDeviceType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func lc(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}
