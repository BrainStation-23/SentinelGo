package peripherals

import (
	"strings"
	"testing"
)

func TestParsePnpDevices(t *testing.T) {
	type tc struct {
		description string
		devType     string
		wantKept    bool
	}
	cases := []tc{
		{"USB Root Hub (USB 3.0)", "USB Device", false},
		{"USB Root Hub (USB 3.1)", "USB Device", false},
		{"Intel USB 3.1 xHC Host Controller", "USB Device", false},
		{"USB Composite Device", "USB Device", false},
		{"Generic USB Hub", "USB Device", false},
		{"4-Port USB Hub", "USB Device", false},
		{"HyperX Alloy Keyboard", "Keyboard", true},
		{"Logitech M720 Mouse", "Mouse or other pointing device", true},
		{"USB Audio Device", "HID Device", true},
		{"SanDisk Cruzer Blade", "USB Device", true},
	}

	var items []map[string]any
	for _, c := range cases {
		items = append(items, map[string]any{
			"Type":        c.devType,
			"Description": c.description,
		})
	}

	got := parsePnpDevices(items)

	// Build a set of descriptions that were returned.
	kept := make(map[string]bool, len(got))
	for _, d := range got {
		kept[d.Description] = true
	}

	for _, c := range cases {
		if c.wantKept && !kept[c.description] {
			t.Errorf("expected %q to be kept, but it was filtered out", c.description)
		}
		if !c.wantKept && kept[c.description] {
			t.Errorf("expected %q to be filtered out as infrastructure, but it was kept", c.description)
		}
	}
}

func TestParseVendorProductFromHardwareID(t *testing.T) {
	tests := []struct {
		name          string
		hwid          string
		wantVendorID  string
		wantProductID string
	}{
		{
			"standard USB hardware ID",
			`USB\VID_046D&PID_C52B&REV_2201`,
			"046D", "C52B",
		},
		{
			"USB HID hardware ID",
			`HID\VID_045E&PID_07A5&REV_0112&MI_01`,
			"045E", "07A5",
		},
		{
			"no VID_/PID_ tokens",
			`ACPI\INT33C6\0`,
			"", "",
		},
		{
			"empty string",
			``,
			"", "",
		},
		{
			"VID only no ampersand",
			`USB\VID_1234`,
			"1234", "",
		},
		{
			"PID at end with no trailing delimiter",
			`USB\VID_ABCD&PID_EF01`,
			"ABCD", "EF01",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vid, pid := parseVendorProductFromHardwareID(tc.hwid)
			if vid != tc.wantVendorID {
				t.Errorf("VendorID = %q, want %q (input %q)", vid, tc.wantVendorID, tc.hwid)
			}
			if pid != tc.wantProductID {
				t.Errorf("ProductID = %q, want %q (input %q)", pid, tc.wantProductID, tc.hwid)
			}
		})
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
		// Infrastructure nodes must not appear — they are always "OK" in PnP even
		// with no external device plugged in.
		descLow := strings.ToLower(d.Description)
		if strings.Contains(descLow, "root hub") {
			t.Errorf("peripheral[%d] %q: USB Root Hub must be filtered out", i, d.Description)
		}
		if strings.Contains(descLow, "host controller") {
			t.Errorf("peripheral[%d] %q: Host Controller must be filtered out", i, d.Description)
		}
		if strings.Contains(descLow, "composite device") {
			t.Errorf("peripheral[%d] %q: USB Composite Device must be filtered out", i, d.Description)
		}
		t.Logf("peripheral[%d]: type=%q desc=%q mfr=%q conn=%q built-in=%v vid=%q pid=%q",
			i, d.Type, d.Description, d.Manufacturer, d.ConnectionType, d.IsBuiltIn, d.VendorID, d.ProductID)
	}
	t.Logf("total peripherals: %d", len(devs))
}
