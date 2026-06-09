package peripherals

import "testing"

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
		// Manufacturer must not be the same as Description (was the inferManufacturer bug)
		if d.Manufacturer != "" && d.Manufacturer == d.Description {
			t.Errorf("peripheral[%d] %q: Manufacturer == Description (inferManufacturer bug)", i, d.Description)
		}
		t.Logf("peripheral[%d]: type=%q desc=%q mfr=%q conn=%q built-in=%v vid=%q pid=%q",
			i, d.Type, d.Description, d.Manufacturer, d.ConnectionType, d.IsBuiltIn, d.VendorID, d.ProductID)
	}
	t.Logf("total peripherals: %d", len(devs))
}
