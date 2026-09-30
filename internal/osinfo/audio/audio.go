package audio

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Get returns the list of audio devices for the current platform.
func Get() []shared.AudioDevice {
	return getAudioDevices()
}

// audioDeviceDeduper accumulates audio devices from multiple OS-specific
// sources, keeping only the first occurrence of each Description|Manufacturer
// pair.
type audioDeviceDeduper struct {
	seen    map[string]bool
	devices []shared.AudioDevice
}

func newAudioDeviceDeduper() *audioDeviceDeduper {
	return &audioDeviceDeduper{seen: make(map[string]bool)}
}

func (d *audioDeviceDeduper) add(incoming []shared.AudioDevice) {
	for _, dev := range incoming {
		key := dev.Description + "|" + dev.Manufacturer
		if !d.seen[key] {
			d.devices = append(d.devices, dev)
			d.seen[key] = true
		}
	}
}

// inferManufacturer returns name as-is — every device gets a manufacturer
// value regardless of whether it is a recognised brand.
func inferManufacturer(name string) string {
	return name
}

// inferDeviceType returns "input", "output", or "" based on keywords in name.
func inferDeviceType(name string) string {
	lower := strings.ToLower(name)
	for _, k := range []string{"speaker", "headphone", "output", "playback", "hdmi", "spdif out", "line out"} {
		if strings.Contains(lower, k) {
			return "output"
		}
	}
	for _, k := range []string{"microphone", "line in", "input", "capture", "recording"} {
		if strings.Contains(lower, k) {
			return "input"
		}
	}
	return ""
}
