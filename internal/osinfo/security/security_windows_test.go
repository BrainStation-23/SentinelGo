package security

import (
	"testing"
)

func TestParseNetshFirewall(t *testing.T) {
	input := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
`
	profiles := parseNetshFirewall(input)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}
	cases := []struct {
		name    string
		enabled bool
	}{
		{"Domain", true},
		{"Private", true},
		{"Public", false},
	}
	for i, c := range cases {
		if profiles[i].Name != c.name {
			t.Errorf("profile[%d]: got name %q, want %q", i, profiles[i].Name, c.name)
		}
		if profiles[i].Enabled != c.enabled {
			t.Errorf("profile[%d] %q: got enabled=%v, want %v", i, c.name, profiles[i].Enabled, c.enabled)
		}
	}
}

func TestParseNetshFirewallAllOff(t *testing.T) {
	input := `
Domain Profile Settings:
State                                 OFF

Private Profile Settings:
State                                 OFF

Public Profile Settings:
State                                 OFF
`
	profiles := parseNetshFirewall(input)
	for _, p := range profiles {
		if p.Enabled {
			t.Errorf("profile %q should be disabled", p.Name)
		}
	}
}

func TestParseRegDWORD(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		valueName string
		want      int
	}{
		{
			name: "hex value 1",
			input: `
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    UEFISecureBootEnabled    REG_DWORD    0x1
`,
			valueName: "UEFISecureBootEnabled",
			want:      1,
		},
		{
			name: "hex value 0",
			input: `
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard
    EnableVirtualizationBasedSecurity    REG_DWORD    0x0
`,
			valueName: "EnableVirtualizationBasedSecurity",
			want:      0,
		},
		{
			name:      "key not found",
			input:     "ERROR: The system was unable to find the specified registry key or value.",
			valueName: "Enabled",
			want:      -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseRegDWORD(c.input, c.valueName)
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestUsbStorStartToState(t *testing.T) {
	cases := []struct {
		v    int
		want string
	}{
		{4, "disabled"}, // SERVICE_DISABLED — Group Policy / MDM enforcement
		{3, "enabled"},  // SERVICE_DEMAND_START
		{2, "enabled"},  // SERVICE_AUTO_START
		{1, "enabled"},  // SERVICE_SYSTEM_START
		{0, "enabled"},  // SERVICE_BOOT_START
		{-1, "unknown"}, // parseRegDWORD sentinel for missing key
		{5, "unknown"},  // unexpected value
	}
	for _, c := range cases {
		got := usbStorStartToState(c.v)
		if got != c.want {
			t.Errorf("usbStorStartToState(%d) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestParseAVProductsJSON(t *testing.T) {
	t.Run("array with one enabled product", func(t *testing.T) {
		// productState 397568 = 0x61100: bits 12-15 = 1 (enabled), bits 4-7 = 0 (up-to-date)
		input := `[{"displayName":"Windows Defender","productState":397568}]`
		products := parseAVProductsJSON(input)
		if len(products) != 1 {
			t.Fatalf("expected 1 product, got %d", len(products))
		}
		if products[0].Name != "Windows Defender" {
			t.Errorf("got name %q", products[0].Name)
		}
		if products[0].Enabled != "enabled" {
			t.Errorf("got enabled=%q, want enabled", products[0].Enabled)
		}
		if products[0].UpToDate != "yes" {
			t.Errorf("got up_to_date=%q, want yes", products[0].UpToDate)
		}
		if products[0].Source != "SecurityCenter2" {
			t.Errorf("got source=%q", products[0].Source)
		}
	})

	t.Run("single object (not array)", func(t *testing.T) {
		input := `{"displayName":"Malwarebytes","productState":266240}`
		products := parseAVProductsJSON(input)
		if len(products) != 1 {
			t.Fatalf("expected 1 product, got %d", len(products))
		}
		if products[0].Name != "Malwarebytes" {
			t.Errorf("got name %q", products[0].Name)
		}
	})

	t.Run("multiple products", func(t *testing.T) {
		input := `[{"displayName":"Windows Defender","productState":397568},{"displayName":"Malwarebytes","productState":266240}]`
		products := parseAVProductsJSON(input)
		if len(products) != 2 {
			t.Fatalf("expected 2 products, got %d", len(products))
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		products := parseAVProductsJSON("{not json}")
		if products != nil {
			t.Errorf("expected nil for invalid JSON, got %v", products)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		products := parseAVProductsJSON("")
		if products != nil {
			t.Errorf("expected nil for empty string, got %v", products)
		}
	})
}
