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

	// lsusb output format: "Bus 001 Device 002: ID 046d:c52b Logitech, Inc. ..."
	// The "ID" token is a standalone word followed by the vendor:product pair.
	if usbOutput, err := shared.RunCommand("lsusb"); err == nil {
		for _, line := range strings.Split(usbOutput, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			// Minimum: Bus N Device N: ID vendor:product [description...]
			if len(parts) < 6 {
				continue
			}
			var vendorID, productID, description string
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
			if vendorID == "" || productID == "" {
				continue
			}
			// Skip USB hub entries — they are infrastructure, not peripherals.
			descLow := strings.ToLower(description)
			if strings.Contains(descLow, "root hub") || descLow == "hub" || strings.HasSuffix(descLow, " hub") {
				continue
			}
			deviceType := determineDeviceType(description, descLow)
			if deviceType == "" {
				deviceType = "USB Device"
			}
			peripherals = append(peripherals, shared.PeripheralDevice{
				Type:           deviceType,
				Description:    description,
				VendorID:       vendorID,
				ProductID:      productID,
				ConnectionType: "USB",
				Status:         "Connected",
			})
		}
	}

	if audioOutput, err := shared.RunCommand("aplay", "-l"); err == nil {
		for _, line := range strings.Split(audioOutput, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "card") {
				continue
			}
			if strings.Contains(line, "[") && strings.Contains(line, "]") {
				start := strings.Index(line, "[") + 1
				end := strings.Index(line, "]")
				if start > 0 && end > start {
					description := line[start:end]
					deviceType := "Audio Device"
					descLower := strings.ToLower(description)
					if strings.Contains(descLower, "microphone") {
						deviceType = "Microphone"
					} else if strings.Contains(descLower, "speaker") {
						deviceType = "Speaker"
					} else if strings.Contains(descLower, "headphone") {
						deviceType = "Headphones"
					}
					peripherals = append(peripherals, shared.PeripheralDevice{
						Type:           deviceType,
						Description:    description,
						ConnectionType: "ALSA Audio",
						IsBuiltIn:      true,
						Status:         "Connected",
					})
				}
			}
		}
	}

	if btOutput, err := shared.RunCommand("bluetoothctl", "devices"); err == nil {
		for _, line := range strings.Split(btOutput, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Device") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				macAddress := parts[1]
				name := strings.Join(parts[2:], " ")
				deviceType := determineDeviceType(name, strings.ToLower(name))
				if deviceType == "" {
					deviceType = "Bluetooth Device"
				}
				peripherals = append(peripherals, shared.PeripheralDevice{
					Type:           deviceType,
					Description:    name,
					SerialNumber:   macAddress,
					ConnectionType: "Bluetooth",
					Status:         "Connected",
				})
			}
		}
	}

	// PCI audio controllers (built-in sound cards not surfaced by ALSA).
	if pciOutput, err := shared.RunCommand("lspci"); err == nil {
		for _, line := range strings.Split(pciOutput, "\n") {
			if !strings.Contains(line, "Audio") && !strings.Contains(line, "Multimedia audio") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				description := strings.TrimSpace(strings.Join(parts[2:], ":"))
				peripherals = append(peripherals, shared.PeripheralDevice{
					Type:           "Audio Device",
					Description:    description,
					ConnectionType: "PCI",
					IsBuiltIn:      true,
					Status:         "Connected",
				})
			}
		}
	}

	return peripherals
}
