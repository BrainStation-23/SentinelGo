package audio

import "sentinelgo/internal/osinfo/shared"

func getAudioDevices() []shared.AudioDevice {
	dd := newAudioDeviceDeduper()

	if output, err := shared.RunPowerShell(
		"Get-PnpDevice | Where-Object {$_.Class -eq 'AudioEndpoint'} | Select-Object FriendlyName, Manufacturer | ConvertTo-Json"); err == nil {
		dd.add(parseWindowsPnpJSON(output))
	}

	if output, err := shared.RunPowerShell(
		"Get-WmiObject Win32_SoundDevice | Select-Object Name, Manufacturer | ConvertTo-Json"); err == nil {
		dd.add(parseWindowsWmiJSON(output))
	}

	return dd.devices
}
