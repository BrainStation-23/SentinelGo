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

	if output, err := shared.RunCommand("lspci", "-nn"); err == nil {
		add(parseLinuxLspciOutput(output))
	}

	if output, err := shared.RunCommand("cat", "/proc/asound/cards"); err == nil {
		add(parseLinuxAsoundCards(output))
	}

	if output, err := shared.RunCommand("lsusb"); err == nil {
		add(parseLinuxLsusbOutput(output))
	}

	return devices
}
