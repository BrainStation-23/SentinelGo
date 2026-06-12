package peripherals

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestDetermineBluetoothDeviceType(t *testing.T) {
	tests := []struct {
		name      string
		majorType string
		minorType string
		want      string
	}{
		// Older macOS format (exact type strings)
		{"audio microphone", "Audio", "Microphone", "Microphone"},
		{"audio speaker", "Audio", "Speaker", "Speaker"},
		{"audio headphones", "Audio", "Headphones", "Headphones"},
		{"audio other", "Audio", "Amplifier", "Audio Device"},
		{"HID keyboard", "HID", "Keyboard", "Keyboard"},
		{"HID mouse", "HID", "Mouse", "Mouse or other pointing device"},
		{"HID gamepad", "HID", "Gamepad", "Game Controller"},
		{"HID other", "HID", "Joystick", "HID Device"},
		{"peripheral", "Peripheral", "", "Peripheral Device"},
		{"unknown major type", "Phone", "Smartphone", "Bluetooth Device"},
		{"empty major type", "", "", "Bluetooth Device"},
		// macOS 13+ format ("Audio/Video" major, full minor strings)
		{"modern audio/video headphones", "Audio/Video", "Headphones", "Headphones"},
		{"modern audio/video microphone", "Audio/Video", "Microphone", "Microphone"},
		{"modern audio/video speaker", "Audio/Video", "Loudspeaker", "Speaker"},
		{"modern audio/video other", "Audio/Video", "VCR", "Audio Device"},
		{"modern peripheral keyboard", "Peripheral", "Keyboard", "Keyboard"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := determineBluetoothDeviceType(tc.majorType, tc.minorType)
			if got != tc.want {
				t.Errorf("determineBluetoothDeviceType(%q, %q) = %q, want %q",
					tc.majorType, tc.minorType, got, tc.want)
			}
		})
	}
}

func TestParseBTDeviceList_ModernFormat(t *testing.T) {
	// Mirrors the real macOS 13+ SPBluetoothDataType device entry structure.
	devices := []any{
		map[string]any{
			"_name":                            "AirPods Pro",
			"device_address":                   "11-22-33-44-55-66",
			"device_majorClassOfDevice_string": "Audio/Video",
			"device_minorClassOfDevice_string": "Headphones",
			"device_connected":                 "attrib_yes",
			"device_vendorID":                  "0x004C",
			"device_productID":                 "0x200F",
		},
		map[string]any{
			"_name":                            "Magic Mouse",
			"device_address":                   "AA-BB-CC-DD-EE-FF",
			"device_majorClassOfDevice_string": "Peripheral",
			"device_minorClassOfDevice_string": "Mouse",
			"device_connected":                 "attrib_no", // paired but not connected
		},
	}
	var peripherals []shared.PeripheralDevice
	parseBTDeviceList(devices, &peripherals)

	if len(peripherals) != 2 {
		t.Fatalf("expected 2 BT devices, got %d", len(peripherals))
	}

	ap := peripherals[0]
	if ap.Description != "AirPods Pro" {
		t.Errorf("AirPods desc = %q", ap.Description)
	}
	if ap.Type != "Headphones" {
		t.Errorf("AirPods type = %q, want Headphones", ap.Type)
	}
	if ap.Status != "Connected" {
		t.Errorf("AirPods status = %q, want Connected", ap.Status)
	}
	if ap.SerialNumber != "11-22-33-44-55-66" {
		t.Errorf("AirPods serial = %q", ap.SerialNumber)
	}
	if ap.ConnectionType != "Bluetooth" {
		t.Errorf("AirPods connectionType = %q", ap.ConnectionType)
	}

	mouse := peripherals[1]
	if mouse.Type != "Mouse or other pointing device" {
		t.Errorf("Magic Mouse type = %q", mouse.Type)
	}
	if mouse.Status != "Paired" {
		t.Errorf("Magic Mouse status = %q, want Paired (device_connected=attrib_no)", mouse.Status)
	}
}

func TestParseBTDeviceList_OldFormat(t *testing.T) {
	// Older macOS format used "device_name" and "device_majorType"/"device_minorType".
	devices := []any{
		map[string]any{
			"device_name":      "Keyboard",
			"device_address":   "11-22-33-44-55-66",
			"device_majorType": "HID",
			"device_minorType": "Keyboard",
		},
	}
	var peripherals []shared.PeripheralDevice
	parseBTDeviceList(devices, &peripherals)

	if len(peripherals) != 1 {
		t.Fatalf("expected 1 BT device, got %d", len(peripherals))
	}
	if peripherals[0].Type != "Keyboard" {
		t.Errorf("type = %q, want Keyboard", peripherals[0].Type)
	}
	if peripherals[0].Description != "Keyboard" {
		t.Errorf("desc = %q", peripherals[0].Description)
	}
}

func TestParseBTDeviceList_SectionHeaderNesting(t *testing.T) {
	// Some macOS versions nest devices under a section header entry with _items.
	devices := []any{
		map[string]any{
			"_name": "Input Devices",
			"_items": []any{
				map[string]any{
					"_name":                            "Magic Keyboard",
					"device_address":                   "AA-BB-CC-DD-EE-FF",
					"device_majorClassOfDevice_string": "Peripheral",
					"device_minorClassOfDevice_string": "Keyboard",
					"device_connected":                 "attrib_yes",
				},
			},
		},
	}
	var peripherals []shared.PeripheralDevice
	parseBTDeviceList(devices, &peripherals)

	if len(peripherals) != 1 {
		t.Fatalf("expected 1 BT device (nested in section header), got %d", len(peripherals))
	}
	if peripherals[0].Description != "Magic Keyboard" {
		t.Errorf("desc = %q, want Magic Keyboard", peripherals[0].Description)
	}
	if peripherals[0].Type != "Keyboard" {
		t.Errorf("type = %q, want Keyboard", peripherals[0].Type)
	}
}

func TestParseUSBItems_SkipsHostControllers(t *testing.T) {
	// USB31Bus entries have a "host_controller" field — they are internal bus
	// controllers and must not appear in the peripherals list.
	items := []any{
		map[string]any{
			"_name":           "USB31Bus",
			"host_controller": "AppleT8112USBXHCI",
		},
		map[string]any{
			"_name":           "USB31Bus",
			"host_controller": "AppleT8112USBXHCI",
			// with a real device nested underneath
			"_items": []any{
				map[string]any{
					"_name":        "Logitech USB Receiver",
					"vendor_id":    "0x046d",
					"product_id":   "0xc52b",
					"manufacturer": "Logitech",
				},
			},
		},
	}
	var peripherals []shared.PeripheralDevice
	parseUSBItems(items, &peripherals, "USB")

	// Only the nested Logitech device should appear, not the two USB31Bus controllers.
	if len(peripherals) != 1 {
		t.Fatalf("expected 1 peripheral (child of bus), got %d: %+v", len(peripherals), peripherals)
	}
	if peripherals[0].Description != "Logitech USB Receiver" {
		t.Errorf("desc = %q, want Logitech USB Receiver", peripherals[0].Description)
	}
}

func TestParseThunderboltItems_SkipsBusControllers(t *testing.T) {
	// thunderboltusb4_bus_* entries are host port controllers — they carry a
	// "domain_uuid_key" and should not be listed as peripheral devices.
	items := []any{
		map[string]any{
			"_name":            "thunderboltusb4_bus_0",
			"device_name_key":  "MacBook Pro",
			"domain_uuid_key":  "9C7FA856-A18E-4A29-94F2-5BE2543CE06A",
			"vendor_name_key":  "Apple Inc.",
			"route_string_key": "0",
		},
		map[string]any{
			"_name":            "thunderboltusb4_bus_0",
			"device_name_key":  "MacBook Pro",
			"domain_uuid_key":  "9C7FA856-A18E-4A29-94F2-5BE2543CE06A",
			"vendor_name_key":  "Apple Inc.",
			"route_string_key": "0",
			// with a real external Thunderbolt device connected
			"_items": []any{
				map[string]any{
					"_name":           "Thunderbolt Display",
					"vendor_name_key": "Apple Inc.",
					"serial_number":   "C02K1234F8J2",
				},
			},
		},
	}
	var peripherals []shared.PeripheralDevice
	parseThunderboltItems(items, &peripherals)

	// Only the nested display should appear, not the bus controllers.
	if len(peripherals) != 1 {
		t.Fatalf("expected 1 Thunderbolt peripheral, got %d: %+v", len(peripherals), peripherals)
	}
	if peripherals[0].Description != "Thunderbolt Display" {
		t.Errorf("desc = %q, want Thunderbolt Display", peripherals[0].Description)
	}
	if peripherals[0].Manufacturer != "Apple Inc." {
		t.Errorf("mfr = %q, want Apple Inc.", peripherals[0].Manufacturer)
	}
}

func TestParseUSBItems_IncludesUnknownTypes(t *testing.T) {
	// USB devices whose names don't match any known category should
	// now be included with Type="USB Device" rather than silently dropped.
	items := []any{
		map[string]any{
			"_name":        "Logitech USB Receiver",
			"vendor_id":    "0x046d",
			"product_id":   "0xc52b",
			"manufacturer": "Logitech",
		},
		map[string]any{
			"_name":      "USB Keyboard",
			"vendor_id":  "0x1234",
			"product_id": "0x0001",
		},
	}

	var peripherals []shared.PeripheralDevice
	parseUSBItems(items, &peripherals, "USB")

	if len(peripherals) != 2 {
		t.Fatalf("expected 2 devices (including unknown-type), got %d", len(peripherals))
	}

	receiver := peripherals[0]
	if receiver.Type != "USB Device" {
		t.Errorf("unknown device type = %q, want USB Device", receiver.Type)
	}
	if receiver.Description != "Logitech USB Receiver" {
		t.Errorf("Description = %q, want Logitech USB Receiver", receiver.Description)
	}
	if receiver.Manufacturer != "Logitech" {
		t.Errorf("Manufacturer = %q, want Logitech", receiver.Manufacturer)
	}

	kbd := peripherals[1]
	if kbd.Type != "Keyboard" {
		t.Errorf("keyboard type = %q, want Keyboard", kbd.Type)
	}
}

func TestParseUSBItems_SkipsEmptyName(t *testing.T) {
	items := []any{
		map[string]any{"vendor_id": "0x046d", "product_id": "0xc52b"},
	}
	var peripherals []shared.PeripheralDevice
	parseUSBItems(items, &peripherals, "USB")
	if len(peripherals) != 0 {
		t.Errorf("expected 0 devices for item with no _name, got %d", len(peripherals))
	}
}

func TestParseHIDDevices(t *testing.T) {
	ioregOutput := `
  | +-o IOHIDKeyboard  <class IOHIDKeyboard>
  | |   "Product" = "Apple Internal Keyboard / Trackpad"
  | |   "Manufacturer" = "Apple Inc."
  | |   "VendorID" = 1452
  | |   "ProductID" = 641
  | +-o IOHIDPointing  <class IOHIDPointing>
  | |   "Product" = "Magic Mouse"
  | |   "Manufacturer" = "Apple"
  | |   "VendorID" = 1452
  | |   "ProductID" = 613
`
	var peripherals []shared.PeripheralDevice
	parseHIDDevices(ioregOutput, &peripherals)

	if len(peripherals) != 2 {
		t.Fatalf("expected 2 HID devices, got %d", len(peripherals))
	}

	kbd := peripherals[0]
	if kbd.Description != "Apple Internal Keyboard / Trackpad" {
		t.Errorf("kbd.Description = %q", kbd.Description)
	}
	if kbd.Type != "Keyboard" {
		t.Errorf("kbd.Type = %q, want Keyboard", kbd.Type)
	}
	if kbd.Manufacturer != "Apple Inc." {
		t.Errorf("kbd.Manufacturer = %q, want Apple Inc.", kbd.Manufacturer)
	}

	mouse := peripherals[1]
	if mouse.Type != "Mouse or other pointing device" {
		t.Errorf("mouse.Type = %q, want Mouse or other pointing device", mouse.Type)
	}
}

func TestGetPeripherals_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	devs := Get()
	for i, d := range devs {
		if d.Description == "" {
			t.Errorf("peripheral[%d] has empty Description", i)
		}
		if d.Type == "" {
			t.Errorf("peripheral[%d] %q has empty Type", i, d.Description)
		}
		if d.Manufacturer != "" && d.Manufacturer == d.Description {
			t.Errorf("peripheral[%d] %q: Manufacturer == Description (inferManufacturer bug)", i, d.Description)
		}
		t.Logf("peripheral[%d]: type=%q desc=%q mfr=%q conn=%q built-in=%v",
			i, d.Type, d.Description, d.Manufacturer, d.ConnectionType, d.IsBuiltIn)
	}
	t.Logf("total peripherals: %d", len(devs))
}
