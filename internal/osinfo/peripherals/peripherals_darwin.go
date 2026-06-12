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

		// Skip internal host bus controllers — they have a "host_controller" field
		// but no vendor_id or manufacturer (e.g. "USB31Bus").
		_, isHostController := m["host_controller"]

		if name != "" && !isHostController {
			devType := determineDeviceType(name, strings.ToLower(name))
			if devType == "" {
				devType = "USB Device"
			}
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

// parseBluetoothItems iterates the top-level SPBluetoothDataType array and
// dispatches each entry's device list to parseBTDeviceList.
func parseBluetoothItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if devices, ok := m["device_title"].([]any); ok {
			parseBTDeviceList(devices, peripherals)
		}
	}
}

// parseBTDeviceList processes an array of Bluetooth device entries.
// It handles both the flat list format (older macOS) and the section-header
// format where device_title contains group objects that nest actual devices
// under "_items" (some macOS versions).
func parseBTDeviceList(devices []any, peripherals *[]shared.PeripheralDevice) {
	for _, device := range devices {
		devMap, ok := device.(map[string]any)
		if !ok {
			continue
		}
		// Section-header nesting: some macOS versions group devices under a
		// header entry with _items containing the actual device records.
		if items, ok := devMap["_items"].([]any); ok {
			parseBTDeviceList(items, peripherals)
			continue
		}

		// Device name: macOS 13+ uses "_name"; older versions used "device_name".
		name, _ := devMap["_name"].(string)
		if name == "" {
			name, _ = devMap["device_name"].(string)
		}
		if name == "" {
			continue
		}

		address, _ := devMap["device_address"].(string)

		// Major/minor type: macOS 13+ uses *ClassOfDevice_string; older used *Type.
		majorType, _ := devMap["device_majorClassOfDevice_string"].(string)
		if majorType == "" {
			majorType, _ = devMap["device_majorType"].(string)
		}
		minorType, _ := devMap["device_minorClassOfDevice_string"].(string)
		if minorType == "" {
			minorType, _ = devMap["device_minorType"].(string)
		}

		vendorID, _ := devMap["device_vendorID"].(string)
		productID, _ := devMap["device_productID"].(string)

		// Connection status: "attrib_yes" = currently connected; "attrib_no" = paired
		// but not connected. Absent in older formats — treat as Connected in that case.
		status := "Connected"
		if connected, _ := devMap["device_connected"].(string); connected == "attrib_no" {
			status = "Paired"
		}

		*peripherals = append(*peripherals, shared.PeripheralDevice{
			Type:           determineBluetoothDeviceType(majorType, minorType),
			Description:    name,
			SerialNumber:   address,
			VendorID:       vendorID,
			ProductID:      productID,
			ConnectionType: "Bluetooth",
			Status:         status,
		})
	}
}

func parseThunderboltItems(items []any, peripherals *[]shared.PeripheralDevice) {
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["_name"].(string)
		// "vendor_name_key" is the correct field in modern system_profiler output;
		// "vendor_name" was used in older versions.
		vendorName, _ := m["vendor_name_key"].(string)
		if vendorName == "" {
			vendorName, _ = m["vendor_name"].(string)
		}
		serialNum, _ := m["serial_number"].(string)

		// Skip host bus controller entries — they represent the MacBook's own
		// Thunderbolt ports, not attached external devices.  Bus entries carry a
		// "domain_uuid_key" (port-level UUID) and route_string_key == "0"
		// (host node).  External devices appear as _items under these entries.
		_, isBusController := m["domain_uuid_key"]

		if name != "" && !isBusController {
			*peripherals = append(*peripherals, shared.PeripheralDevice{
				Type:           "Thunderbolt Device",
				Description:    name,
				Manufacturer:   vendorName,
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
			*peripherals = append(*peripherals, shared.PeripheralDevice{
				Type:           "FireWire Device",
				Description:    name,
				Manufacturer:   vendorName,
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

// determineBluetoothDeviceType classifies a Bluetooth device from its major/minor
// type strings.  It uses Contains rather than exact equality to handle both the
// older format ("Audio", "HID") and the modern macOS 13+ format
// ("Audio/Video", "Peripheral").
func determineBluetoothDeviceType(majorType, minorType string) string {
	minorLower := strings.ToLower(minorType)
	// Minor type is more specific — check it first.
	switch {
	case strings.Contains(minorLower, "headphone"):
		return "Headphones"
	case strings.Contains(minorLower, "microphone"):
		return "Microphone"
	case strings.Contains(minorLower, "speaker"):
		return "Speaker"
	case strings.Contains(minorLower, "keyboard"):
		return "Keyboard"
	case strings.Contains(minorLower, "mouse") || strings.Contains(minorLower, "pointing"):
		return "Mouse or other pointing device"
	case strings.Contains(minorLower, "gamepad"):
		return "Game Controller"
	}
	// Fall back to major type.
	majorLower := strings.ToLower(majorType)
	switch {
	case strings.Contains(majorLower, "audio"):
		return "Audio Device"
	case majorLower == "hid" || strings.HasPrefix(majorLower, "hid "):
		return "HID Device"
	case strings.Contains(majorLower, "peripheral"):
		return "Peripheral Device"
	case strings.Contains(majorLower, "hid"):
		return "HID Device"
	}
	return "Bluetooth Device"
}
