package audio

import "sentinelgo/internal/osinfo/shared"

func getAudioDevices() []shared.AudioDevice {
	dd := newAudioDeviceDeduper()

	if output, err := shared.RunCommand("system_profiler", "SPAudioDataType"); err == nil {
		dd.add(parseDarwinAudioOutput(output))
	}

	return dd.devices
}
