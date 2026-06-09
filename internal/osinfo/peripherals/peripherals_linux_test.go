package peripherals

import "testing"

const sampleInputDevices = `
I: Bus=0011 Vendor=0001 Product=0001 Version=ab54
N: Name="AT Translated Set 2 keyboard"
P: Phys=isa0060/serio0/input0
S: Sysfs=/devices/platform/i8042/serio0/input/input0
U: Uniq=
H: Handlers=sysrq kbd event0 leds

I: Bus=0011 Vendor=0002 Product=0001 Version=0000
N: Name="PS/2 Generic Mouse"
P: Phys=isa0060/serio1/input0
H: Handlers=mouse0 event1

I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech USB Receiver"
P: Phys=usb-0000:00:14.0-2/input0
H: Handlers=mouse1 event2

I: Bus=0003 Vendor=04f3 Product=0235 Version=0001
N: Name="Elan Touchpad"
P: Phys=i2c-4/input0
H: Handlers=mouse2 event3

I: Bus=0003 Vendor=046d Product=c31c Version=0064
N: Name="Logitech USB Keyboard"
P: Phys=usb-0000:00:14.0-3/input0
H: Handlers=sysrq kbd event4 leds

I: Bus=0001 Vendor=0000 Product=0000 Version=0000
N: Name="Power Button"
P: Phys=LNXPWRBN/button/input0
H: Handlers=kbd event5
`

func TestParseInputDevices(t *testing.T) {
	devices := parseInputDevices(sampleInputDevices)

	// Expected:
	// 1. AT Translated Set 2 keyboard (i8042, Bus=0011) → Keyboard, IsBuiltIn=true
	// 2. PS/2 Generic Mouse (Bus=0011) → Mouse, IsBuiltIn=true
	// 3. Logitech USB Receiver (Bus=0003) → Mouse, IsBuiltIn=false
	// 4. Elan Touchpad (Bus=0003) → Mouse, IsBuiltIn=false
	// 5. Logitech USB Keyboard (Bus=0003) → Keyboard, IsBuiltIn=false
	// 6. Power Button (Bus=0001) → type includes kbd → Keyboard, IsBuiltIn=true
	//    (Power Button bus=0001 is not USB/BT so IsBuiltIn=true — acceptable)

	if len(devices) != 6 {
		t.Fatalf("expected 6 devices, got %d", len(devices))
	}

	type want struct {
		desc      string
		devType   string
		isBuiltIn bool
	}
	expected := []want{
		{"AT Translated Set 2 keyboard", "Keyboard", true},
		{"PS/2 Generic Mouse", "Mouse or other pointing device", true},
		{"Logitech USB Receiver", "Mouse or other pointing device", false},
		{"Elan Touchpad", "Mouse or other pointing device", false},
		{"Logitech USB Keyboard", "Keyboard", false},
		{"Power Button", "Keyboard", true},
	}

	for i, e := range expected {
		d := devices[i]
		if d.Description != e.desc {
			t.Errorf("device[%d]: Description = %q, want %q", i, d.Description, e.desc)
		}
		if d.Type != e.devType {
			t.Errorf("device[%d] %q: Type = %q, want %q", i, d.Description, d.Type, e.devType)
		}
		if d.IsBuiltIn != e.isBuiltIn {
			t.Errorf("device[%d] %q: IsBuiltIn = %v, want %v", i, d.Description, d.IsBuiltIn, e.isBuiltIn)
		}
	}
}

func TestParseInputDevices_EmptyInput(t *testing.T) {
	devices := parseInputDevices("")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices for empty input, got %d", len(devices))
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
		t.Logf("peripheral[%d]: type=%q desc=%q conn=%q built-in=%v vid=%q pid=%q",
			i, d.Type, d.Description, d.ConnectionType, d.IsBuiltIn, d.VendorID, d.ProductID)
	}
	t.Logf("total peripherals: %d", len(devs))
}
