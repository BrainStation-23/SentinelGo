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

	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-PnpDevice | Where-Object {$_.Class -eq 'AudioEndpoint'} | Select-Object FriendlyName, Manufacturer | ConvertTo-Json"); err == nil {
		add(parseWindowsPnpJSON(output))
	}

	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_SoundDevice | Select-Object Name, Manufacturer | ConvertTo-Json"); err == nil {
		add(parseWindowsWmiJSON(output))
	}

	return devices
}
