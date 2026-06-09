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
