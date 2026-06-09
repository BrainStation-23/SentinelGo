package audio

// parse.go contains pure-string parse functions extracted from each platform's
// getAudioDevices implementation. Keeping them in a file with no OS-specific
// suffix means they compile on every platform and can be unit-tested anywhere.

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// parseDarwinAudioOutput parses the text output of `system_profiler SPAudioDataType`.
//
// Device blocks are detected as section headers: a trimmed line that ends with
// ":" and contains no ": " (which would make it a key-value property). Each
// block's Manufacturer, Input Source, and Output Source keys populate the struct.
func parseDarwinAudioOutput(output string) []shared.AudioDevice {
	var devices []shared.AudioDevice
	seen := make(map[string]bool)
	var cur *shared.AudioDevice

	flush := func() {
		if cur == nil || cur.Description == "" {
			return
		}
		if cur.Manufacturer == "" {
			cur.Manufacturer = inferManufacturer(cur.Description)
		}
		key := cur.Description + "|" + cur.Manufacturer
		if !seen[key] {
			devices = append(devices, *cur)
			seen[key] = true
		}
		cur = nil
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Property line: "Key: Value"
		if idx := strings.Index(trimmed, ": "); idx > 0 {
			if cur == nil {
				continue
			}
			key := trimmed[:idx]
			value := trimmed[idx+2:]
			switch key {
			case "Manufacturer":
				cur.Manufacturer = value
			case "Input Source":
				_ = value
				switch cur.Type {
				case "output":
					cur.Type = "input/output"
				case "":
					cur.Type = "input"
				}
			case "Output Source":
				_ = value
				switch cur.Type {
				case "input":
					cur.Type = "input/output"
				case "":
					cur.Type = "output"
				}
			}
			continue
		}

		// Section header: trimmed line ends with ":" and has no ": " inside.
		if strings.HasSuffix(trimmed, ":") {
			name := strings.TrimSuffix(trimmed, ":")
			// Skip known non-device section headers.
			if name == "Audio" || name == "Devices" {
				continue
			}
			// system_profiler indents device names at 8 spaces and property keys
			// at 10+ spaces. An empty-value property ("Manufacturer:") sits at
			// deep indent and must not be mistaken for a new device block.
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if cur != nil && indent >= 10 {
				continue
			}
			flush()
			cur = &shared.AudioDevice{Description: name}
		}
	}
	flush()

	return devices
}

// parseLinuxLspciOutput parses `lspci -nn` output for audio/multimedia devices.
//
// Example line:
//
//	00:1f.3 Audio device [0403]: Intel Corporation Alder Lake PCH-P HD Audio [8086:51c8] (rev 01)
func parseLinuxLspciOutput(output string) []shared.AudioDevice {
	var devices []shared.AudioDevice
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "audio") && !strings.Contains(lower, "multimedia") {
			continue
		}
		// Split on ":" at most 3 parts: address, class, description.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[2])
		// Strip trailing PCI ID "[xxxx:xxxx] ..." and revision info.
		if idx := strings.Index(name, "["); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if name == "" {
			continue
		}
		manufacturer := inferManufacturer(name)
		key := name + "|" + manufacturer
		if !seen[key] {
			devices = append(devices, shared.AudioDevice{Description: name, Manufacturer: manufacturer})
			seen[key] = true
		}
	}

	return devices
}

// parseLinuxAsoundCards parses `/proc/asound/cards`.
//
// Index lines contain "]:" which separates the card handle from the
// driver/description pair "driver - card name". Continuation lines (deeper
// indentation, no "]:") are skipped.
//
// Example:
//
//	0 [PCH   ]: HDA-Intel - HDA Intel PCH
//	            HDA Intel PCH at 0x603c... irq 165
func parseLinuxAsoundCards(output string) []shared.AudioDevice {
	var devices []shared.AudioDevice
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		// Index lines are the only ones containing "]:"
		colonIdx := strings.Index(line, "]:")
		if colonIdx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[colonIdx+2:])
		// Format after "]:": "HDA-Intel - HDA Intel PCH"
		// Take the part after " - " as the human-readable card name.
		if dashIdx := strings.LastIndex(rest, " - "); dashIdx >= 0 {
			rest = strings.TrimSpace(rest[dashIdx+3:])
		}
		if rest == "" {
			continue
		}
		manufacturer := inferManufacturer(rest)
		key := rest + "|" + manufacturer
		if !seen[key] {
			devices = append(devices, shared.AudioDevice{Description: rest, Manufacturer: manufacturer})
			seen[key] = true
		}
	}

	return devices
}

// parseLinuxLsusbOutput parses `lsusb` for USB audio/sound devices.
//
// Example line:
//
//	Bus 001 Device 003: ID 0bda:5400 Realtek Semiconductor Corp. USB Audio Device
func parseLinuxLsusbOutput(output string) []shared.AudioDevice {
	var devices []shared.AudioDevice
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		isAudio := strings.Contains(lower, "audio") ||
			strings.Contains(lower, "sound") ||
			strings.Contains(lower, "headset") ||
			strings.Contains(lower, "headphone") ||
			strings.Contains(lower, "microphone")
		if !isAudio {
			continue
		}
		// Fields: Bus(0) NNN(1) Device(2) NNN:(3) ID(4) xxxx:xxxx(5) Desc...(6+)
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		desc := strings.Join(fields[6:], " ")
		manufacturer := inferManufacturer(desc)
		key := desc + "|" + manufacturer
		if !seen[key] {
			devices = append(devices, shared.AudioDevice{Description: desc, Manufacturer: manufacturer})
			seen[key] = true
		}
	}

	return devices
}

// parseWindowsPnpJSON parses JSON from:
//
//	Get-PnpDevice | Where-Object {$_.Class -eq 'AudioEndpoint'} | Select-Object FriendlyName, Manufacturer | ConvertTo-Json
//
// PowerShell returns a single object (not array) when there is only one device,
// so both forms are handled.
func parseWindowsPnpJSON(output string) []shared.AudioDevice {
	return parseWindowsJSON(output, "FriendlyName", "Manufacturer")
}

// parseWindowsWmiJSON parses JSON from:
//
//	Get-WmiObject Win32_SoundDevice | Select-Object Name, Manufacturer | ConvertTo-Json
func parseWindowsWmiJSON(output string) []shared.AudioDevice {
	return parseWindowsJSON(output, "Name", "Manufacturer")
}

// parseWindowsJSON is the shared parser for both Windows sources, parameterised
// by the name field key (FriendlyName vs Name).
func parseWindowsJSON(output, nameKey, mfrKey string) []shared.AudioDevice {
	var devices []shared.AudioDevice
	seen := make(map[string]bool)

	var rows []map[string]any
	if err := json.Unmarshal([]byte(output), &rows); err != nil {
		// PowerShell returns a single object when there is exactly one device.
		var single map[string]any
		if err2 := json.Unmarshal([]byte(output), &single); err2 != nil {
			return devices
		}
		rows = []map[string]any{single}
	}

	for _, row := range rows {
		name, _ := row[nameKey].(string)
		if name == "" {
			continue
		}
		manufacturer, _ := row[mfrKey].(string)
		if manufacturer == "" || manufacturer == "Microsoft" {
			manufacturer = inferManufacturer(name)
		}
		devType := inferDeviceType(name)
		key := name + "|" + manufacturer
		if !seen[key] {
			devices = append(devices, shared.AudioDevice{
				Description:  name,
				Manufacturer: manufacturer,
				Type:         devType,
			})
			seen[key] = true
		}
	}

	return devices
}
