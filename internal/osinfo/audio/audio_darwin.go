package audio

import "sentinelgo/internal/osinfo/shared"

func getAudioDevices() []shared.AudioDevice {
	seen := make(map[string]bool)
	var devices []shared.AudioDevice

	add := func(incoming []shared.AudioDevice) {
		for _, d := range incoming {
			key := d.Description + "|" + d.Manufacturer
			if !seen[key] {
				devices = append(devices, d)
				seen[key] = true
			}
		}
	}

	if output, err := shared.RunCommand("system_profiler", "SPAudioDataType"); err == nil {
		add(parseDarwinAudioOutput(output))
	}

	return devices
}
