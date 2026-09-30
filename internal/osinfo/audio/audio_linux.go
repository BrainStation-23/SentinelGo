package audio

import "sentinelgo/internal/osinfo/shared"

func getAudioDevices() []shared.AudioDevice {
	dd := newAudioDeviceDeduper()

	if output, err := shared.RunCommand("lspci", "-nn"); err == nil {
		dd.add(parseLinuxLspciOutput(output))
	}

	if output, err := shared.RunCommand("cat", "/proc/asound/cards"); err == nil {
		dd.add(parseLinuxAsoundCards(output))
	}

	if output, err := shared.RunCommand("lsusb"); err == nil {
		dd.add(parseLinuxLsusbOutput(output))
	}

	return dd.devices
}
