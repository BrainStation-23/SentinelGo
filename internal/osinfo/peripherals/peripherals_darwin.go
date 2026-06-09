package peripherals

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getPeripherals() []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice

	if output, err := shared.RunCommand("system_profiler", "SPUSBDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if usbRaw, ok := result["SPUSBDataType"]; ok {
				if usbItems, ok := usbRaw.([]any); ok {
					parseUSBItems(usbItems, &peripherals, "USB")
				}
			}
		}
	}

	if output, err := shared.RunCommand("system_profiler", "SPBluetoothDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if btRaw, ok := result["SPBluetoothDataType"]; ok {
				if btItems, ok := btRaw.([]any); ok {
					parseBluetoothItems(btItems, &peripherals)
				}
			}
		}
	}

	if output, err := shared.RunCommand("system_profiler", "SPThunderboltDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if tbRaw, ok := result["SPThunderboltDataType"]; ok {
				if tbItems, ok := tbRaw.([]any); ok {
					parseThunderboltItems(tbItems, &peripherals)
				}
			}
		}
	}

	if output, err := shared.RunCommand("system_profiler", "SPFireWireDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if fwRaw, ok := result["SPFireWireDataType"]; ok {
				if fwItems, ok := fwRaw.([]any); ok {
					parseFireWireItems(fwItems, &peripherals)
				}
			}
		}
	}

	if output, err := shared.RunCommand("system_profiler", "SPAudioDataType", "-json"); err == nil {
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err == nil {
			if audioRaw, ok := result["SPAudioDataType"]; ok {
				if audioItems, ok := audioRaw.([]any); ok {
					parseAudioItems(audioItems, &peripherals)
				}
			}
		}
	}

	if ioregOutput, err := shared.RunCommand("ioreg", "-p", "IODeviceTree", "-r", "-n", "IOHIDSystem"); err == nil {
		parseHIDDevices(ioregOutput, &peripherals)
	}

	return peripherals
}

func parseUSBItems(items []any, peripherals *[]shared.PeripheralDevice, connectionType string) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["_name"].(string)
		manufacturer, _ := m["manufacturer"].(string)
		serialNum, _ := m["serial_num"].(string)
		vendorID, _ := m["vendor_id"].(string)
		productID, _ := m["product_id"].(string)
		locationID, _ := m["location_id"].(string)

		devType := determineDeviceType(name, strings.ToLower(name))
		if devType == "" {
			devType = "USB Device"
		}
		if name != "" {
			*peripherals = append(*peripherals, shared.PeripheralDevice{
				Type:           devType,
				Description:    name,
				Manufacturer:   manufacturer,
				SerialNumber:   serialNum,
				VendorID:       vendorID,
				ProductID:      productID,
				Location:       locationID,
				ConnectionType: connectionType,
				IsBuiltIn: strings.Contains(strings.ToLower(name), "built-in") ||
					strings.Contains(strings.ToLower(name), "internal"),
				Status: "Connected",
			})
		}
		if children, ok := m["_items"].([]any); ok {
			parseUSBItems(children, peripherals, connectionType)
		}
	}
}

func parseBluetoothItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if devices, ok := m["device_title"].([]any); ok {
			for _, device := range devices {
				if devMap, ok := device.(map[string]any); ok {
					name, _ := devMap["device_name"].(string)
					address, _ := devMap["device_address"].(string)
					majorType, _ := devMap["device_majorType"].(string)
					minorType, _ := devMap["device_minorType"].(string)
					if name != "" {
						*peripherals = append(*peripherals, shared.PeripheralDevice{
							Type:           determineBluetoothDeviceType(majorType, minorType),
							Description:    name,
							SerialNumber:   address,
							ConnectionType: "Bluetooth",
							Status:         "Connected",
						})
					}
				}
			}
		}
	}
}

func parseThunderboltItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["_name"].(string)
		vendorName, _ := m["vendor_name"].(string)
		serialNum, _ := m["serial_number"].(string)
		if name != "" {
			manufacturer := vendorName
			*peripherals = append(*peripherals, shared.PeripheralDevice{
				Type:           "Thunderbolt Device",
				Description:    name,
				Manufacturer:   manufacturer,
				SerialNumber:   serialNum,
				ConnectionType: "Thunderbolt",
				Status:         "Connected",
			})
		}
		if children, ok := m["_items"].([]any); ok {
			parseThunderboltItems(children, peripherals)
		}
	}
}

func parseFireWireItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["_name"].(string)
		vendorName, _ := m["vendor_name"].(string)
		if name != "" {
			manufacturer := vendorName
			*peripherals = append(*peripherals, shared.PeripheralDevice{
				Type:           "FireWire Device",
				Description:    name,
				Manufacturer:   manufacturer,
				ConnectionType: "FireWire",
				Status:         "Connected",
			})
		}
		if children, ok := m["_items"].([]any); ok {
			parseFireWireItems(children, peripherals)
		}
	}
}

func parseAudioItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if devices, ok := m["_items"].([]any); ok {
			for _, device := range devices {
				if devMap, ok := device.(map[string]any); ok {
					name, _ := devMap["_name"].(string)
					manufacturer, _ := devMap["manufacturer"].(string)
					if name != "" {
						deviceType := "Audio Device"
						nameLower := strings.ToLower(name)
						if strings.Contains(nameLower, "microphone") {
							deviceType = "Microphone"
						} else if strings.Contains(nameLower, "speaker") {
							deviceType = "Speaker"
						} else if strings.Contains(nameLower, "headphone") {
							deviceType = "Headphones"
						}
						*peripherals = append(*peripherals, shared.PeripheralDevice{
							Type:           deviceType,
							Description:    name,
							Manufacturer:   manufacturer,
							ConnectionType: "Built-in Audio",
							IsBuiltIn:      true,
							Status:         "Connected",
						})
					}
				}
			}
		}
	}
}

func parseHIDDevices(ioregOutput string, peripherals *[]shared.PeripheralDevice) {
	var currentDevice map[string]string
	isCollecting := false

	for _, line := range strings.Split(ioregOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "+-o IOHID") || strings.Contains(line, "IOHIDDevice") {
			if currentDevice != nil {
				addHIDDeviceFromMap(currentDevice, peripherals)
			}
			currentDevice = make(map[string]string)
			isCollecting = true
		} else if isCollecting && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.Trim(strings.TrimLeft(strings.TrimSpace(parts[0]), "| "), `"`)
				value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				currentDevice[key] = value
			}
		}
	}
	if currentDevice != nil {
		addHIDDeviceFromMap(currentDevice, peripherals)
	}
}

func addHIDDeviceFromMap(deviceMap map[string]string, peripherals *[]shared.PeripheralDevice) {
	name := deviceMap["Product"]
	manufacturer := deviceMap["Manufacturer"]
	vendorID := deviceMap["VendorID"]
	productID := deviceMap["ProductID"]

	if name != "" {
		deviceType := determineDeviceType(name, strings.ToLower(name))
		if deviceType == "" {
			deviceType = "HID Device"
		}
		*peripherals = append(*peripherals, shared.PeripheralDevice{
			Type:           deviceType,
			Description:    name,
			Manufacturer:   manufacturer,
			VendorID:       fmt.Sprintf("%v", vendorID),
			ProductID:      fmt.Sprintf("%v", productID),
			ConnectionType: "Built-in",
			IsBuiltIn:      true,
			Status:         "Connected",
		})
	}
}

func determineBluetoothDeviceType(majorType, minorType string) string {
	switch majorType {
	case "Audio":
		switch {
		case strings.Contains(minorType, "Microphone"):
			return "Microphone"
		case strings.Contains(minorType, "Speaker"):
			return "Speaker"
		case strings.Contains(minorType, "Headphones"):
			return "Headphones"
		}
		return "Audio Device"
	case "HID":
		switch {
		case strings.Contains(minorType, "Keyboard"):
			return "Keyboard"
		case strings.Contains(minorType, "Mouse"):
			return "Mouse or other pointing device"
		case strings.Contains(minorType, "Gamepad"):
			return "Game Controller"
		}
		return "HID Device"
	case "Peripheral":
		return "Peripheral Device"
	default:
		return "Bluetooth Device"
	}
}
