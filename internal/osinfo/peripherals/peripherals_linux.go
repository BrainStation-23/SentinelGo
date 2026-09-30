package peripherals

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// parseInputDevices parses the content of /proc/bus/input/devices into keyboard
// and mouse entries. IsBuiltIn is set to true only when the bus type is not USB
// (0003) or Bluetooth (0005) — i.e. the device is on an internal bus such as
// i8042 or I2C.
func parseInputDevices(content string) []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice
	var devType, devName string
	isBuiltIn := true

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "I: Bus="):
			// Bus codes: 0003=USB, 0005=Bluetooth → external; everything else is internal.
			busField := strings.Fields(strings.TrimPrefix(line, "I: "))[0]
			busHex := strings.TrimPrefix(busField, "Bus=")
			isBuiltIn = busHex != "0003" && busHex != "0005"

		case strings.HasPrefix(line, "N: Name="):
			devName = strings.Trim(strings.TrimPrefix(line, "N: Name="), `"`)

		case strings.HasPrefix(line, "H: Handlers="):
			handlers := strings.ToLower(strings.TrimPrefix(line, "H: Handlers="))
			if strings.Contains(handlers, "kbd") {
				devType = "Keyboard"
			} else if strings.Contains(handlers, "mouse") {
				devType = "Mouse or other pointing device"
			} else {
				devType = ""
			}
			if devType != "" && devName != "" {
				peripherals = append(peripherals, shared.PeripheralDevice{
					Type:           devType,
					Description:    devName,
					ConnectionType: "System Bus",
					IsBuiltIn:      isBuiltIn,
					Status:         "Connected",
				})
			}
			devName = ""
			isBuiltIn = true

		case line == "":
			devName = ""
			isBuiltIn = true
		}
	}
	return peripherals
}

func getPeripherals() []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice

	if content, err := shared.ReadFileContent("/proc/bus/input/devices"); err == nil {
		peripherals = append(peripherals, parseInputDevices(content)...)
	}

	if usbOutput, err := shared.RunCommand("lsusb"); err == nil {
		peripherals = append(peripherals, parseLsusbOutput(usbOutput)...)
	}

	if audioOutput, err := shared.RunCommand("aplay", "-l"); err == nil {
		peripherals = append(peripherals, parseAplayOutput(audioOutput)...)
	}

	peripherals = append(peripherals, collectBluetoothDevices()...)

	// PCI audio controllers (built-in sound cards not surfaced by ALSA).
	if pciOutput, err := shared.RunCommand("lspci"); err == nil {
		peripherals = append(peripherals, parseLspciAudioOutput(pciOutput)...)
	}

	return peripherals
}

// parseLsusbOutput parses `lsusb` output lines of the form
// "Bus 001 Device 002: ID 046d:c52b Logitech, Inc. ..." into peripheral
// entries, skipping malformed lines and USB hub infrastructure.
func parseLsusbOutput(output string) []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice
	for _, line := range strings.Split(output, "\n") {
		if dev, ok := parseLsusbLine(strings.TrimSpace(line)); ok {
			peripherals = append(peripherals, dev)
		}
	}
	return peripherals
}

// parseLsusbLine parses a single lsusb line. It returns false for empty or
// malformed lines and for USB hub entries, which are infrastructure rather
// than peripherals.
func parseLsusbLine(line string) (shared.PeripheralDevice, bool) {
	if line == "" {
		return shared.PeripheralDevice{}, false
	}
	parts := strings.Fields(line)
	// Minimum: Bus N Device N: ID vendor:product [description...]
	if len(parts) < 6 {
		return shared.PeripheralDevice{}, false
	}
	vendorID, productID, description := extractLsusbIDAndDescription(parts)
	if vendorID == "" || productID == "" {
		return shared.PeripheralDevice{}, false
	}
	descLow := strings.ToLower(description)
	if isUSBHubDescription(descLow) {
		return shared.PeripheralDevice{}, false
	}
	deviceType := determineDeviceType(description, descLow)
	if deviceType == "" {
		deviceType = "USB Device"
	}
	return shared.PeripheralDevice{
		Type:           deviceType,
		Description:    description,
		VendorID:       vendorID,
		ProductID:      productID,
		ConnectionType: "USB",
		Status:         "Connected",
	}, true
}

// extractLsusbIDAndDescription pulls the vendor:product ID pair and trailing
// description out of a tokenized lsusb line. The "ID" token is a standalone
// word followed by the vendor:product pair; the description starts after it.
func extractLsusbIDAndDescription(parts []string) (vendorID, productID, description string) {
	for i, part := range parts {
		if part == "ID" && i+1 < len(parts) {
			idParts := strings.SplitN(parts[i+1], ":", 2)
			if len(idParts) == 2 {
				vendorID = idParts[0]
				productID = idParts[1]
			}
		}
		// Description starts after the "vendor:product" token (index of "ID" + 2).
		if i > 5 {
			if description == "" {
				description = part
			} else {
				description += " " + part
			}
		}
	}
	return vendorID, productID, description
}

// isUSBHubDescription reports whether a lowercased lsusb description
// identifies a USB hub — infrastructure to skip, not a peripheral.
func isUSBHubDescription(descLow string) bool {
	return strings.Contains(descLow, "root hub") || descLow == "hub" || strings.HasSuffix(descLow, " hub")
}

// parseAplayOutput parses `aplay -l` output, producing one Audio Device entry
// per "card" line's bracketed device description.
func parseAplayOutput(output string) []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice
	for _, line := range strings.Split(output, "\n") {
		if dev, ok := parseAplayCardLine(strings.TrimSpace(line)); ok {
			peripherals = append(peripherals, dev)
		}
	}
	return peripherals
}

// parseAplayCardLine extracts the bracketed device name from a single
// "cardN: ... [Description]" line, returning false when the line isn't a
// card line or has no bracketed description.
func parseAplayCardLine(line string) (shared.PeripheralDevice, bool) {
	if !strings.HasPrefix(line, "card") {
		return shared.PeripheralDevice{}, false
	}
	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		return shared.PeripheralDevice{}, false
	}
	start := strings.Index(line, "[") + 1
	end := strings.Index(line, "]")
	if start <= 0 || end <= start {
		return shared.PeripheralDevice{}, false
	}
	description := line[start:end]
	return shared.PeripheralDevice{
		Type:           classifyAudioDeviceName(description),
		Description:    description,
		ConnectionType: "ALSA Audio",
		IsBuiltIn:      true,
		Status:         "Connected",
	}, true
}

// classifyAudioDeviceName infers an audio device's specific type from its
// name/description, falling back to the generic "Audio Device" label.
func classifyAudioDeviceName(name string) string {
	nameLower := strings.ToLower(name)
	switch {
	case strings.Contains(nameLower, "microphone"):
		return "Microphone"
	case strings.Contains(nameLower, "speaker"):
		return "Speaker"
	case strings.Contains(nameLower, "headphone"):
		return "Headphones"
	default:
		return "Audio Device"
	}
}

// collectBluetoothDevices lists Bluetooth devices via bluetoothctl. The
// "Connected" subcommand requires bluez ≥ 5.56; on older systems it falls
// back to listing all paired devices rather than silently returning nothing.
func collectBluetoothDevices() []shared.PeripheralDevice {
	btOutput, err := shared.RunCommand("bluetoothctl", "devices", "Connected")
	if err != nil {
		btOutput, err = shared.RunCommand("bluetoothctl", "devices")
	}
	if err != nil {
		return nil
	}
	var peripherals []shared.PeripheralDevice
	for _, line := range strings.Split(btOutput, "\n") {
		if dev, ok := parseBluetoothctlLine(strings.TrimSpace(line)); ok {
			peripherals = append(peripherals, dev)
		}
	}
	return peripherals
}

// parseBluetoothctlLine parses a single "Device XX:XX:... Name" line from
// bluetoothctl output.
func parseBluetoothctlLine(line string) (shared.PeripheralDevice, bool) {
	if !strings.HasPrefix(line, "Device") {
		return shared.PeripheralDevice{}, false
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return shared.PeripheralDevice{}, false
	}
	macAddress := parts[1]
	name := strings.Join(parts[2:], " ")
	deviceType := determineDeviceType(name, strings.ToLower(name))
	if deviceType == "" {
		deviceType = "Bluetooth Device"
	}
	return shared.PeripheralDevice{
		Type:           deviceType,
		Description:    name,
		SerialNumber:   macAddress,
		ConnectionType: "Bluetooth",
		Status:         "Connected",
	}, true
}

// parseLspciAudioOutput extracts PCI audio controllers (built-in sound cards
// not surfaced by ALSA) from `lspci` output.
func parseLspciAudioOutput(output string) []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice
	for _, line := range strings.Split(output, "\n") {
		if dev, ok := parseLspciAudioLine(line); ok {
			peripherals = append(peripherals, dev)
		}
	}
	return peripherals
}

// parseLspciAudioLine matches a single lspci line against Audio/Multimedia
// audio controller entries and extracts the device description.
func parseLspciAudioLine(line string) (shared.PeripheralDevice, bool) {
	if !strings.Contains(line, "Audio") && !strings.Contains(line, "Multimedia audio") {
		return shared.PeripheralDevice{}, false
	}
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return shared.PeripheralDevice{}, false
	}
	description := strings.TrimSpace(strings.Join(parts[2:], ":"))
	return shared.PeripheralDevice{
		Type:           "Audio Device",
		Description:    description,
		ConnectionType: "PCI",
		IsBuiltIn:      true,
		Status:         "Connected",
	}, true
}
