package peripherals

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// parseVendorProductFromHardwareID extracts USB VID and PID from a PnP hardware ID
// string such as "USB\VID_046D&PID_C52B&REV_2201". Returns empty strings when the ID
// is not a USB path or does not contain the expected tokens.
func parseVendorProductFromHardwareID(hwid string) (vendorID, productID string) {
	if !strings.Contains(hwid, "VID_") {
		return "", ""
	}
	if idx := strings.Index(hwid, "VID_"); idx >= 0 {
		rest := hwid[idx+4:]
		end := strings.IndexAny(rest, "&\\ ")
		if end < 0 {
			end = len(rest)
		}
		vendorID = rest[:end]
	}
	if idx := strings.Index(hwid, "PID_"); idx >= 0 {
		rest := hwid[idx+4:]
		end := strings.IndexAny(rest, "&\\ ")
		if end < 0 {
			end = len(rest)
		}
		productID = rest[:end]
	}
	return vendorID, productID
}

func getPeripherals() []shared.PeripheralDevice {
	var peripherals []shared.PeripheralDevice

	// HardwareID is a string[] in WMI/PnP; take the first element in PowerShell so
	// ConvertTo-Json emits a string rather than an array.
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		`Get-PnpDevice | Where-Object {$_.Class -in @('Keyboard','Mouse','USB','HIDClass','Media','Bluetooth') -and $_.Status -eq 'OK'} | `+
			`Select-Object @{N='Type';E={if($_.Class -eq 'Mouse'){'Mouse or other pointing device'} elseif($_.Class -eq 'Keyboard'){'Keyboard'} elseif($_.Class -eq 'HIDClass'){'HID Device'} elseif($_.Class -eq 'Media'){'Audio Device'} elseif($_.Class -eq 'Bluetooth'){'Bluetooth Device'} else {'USB Device'}}}, `+
			`@{N='Description';E={$_.FriendlyName}}, Manufacturer, `+
			`@{N='HardwareID';E={if($_.HardwareID){$_.HardwareID[0]}else{''}}} | ConvertTo-Json -Depth 2`)
	if err == nil {
		output = strings.TrimSpace(output)
		if output != "" {
			var arr []map[string]any
			var obj map[string]any
			if json.Unmarshal([]byte(output), &arr) != nil {
				if json.Unmarshal([]byte(output), &obj) == nil {
					arr = []map[string]any{obj}
				}
			}
			for _, item := range arr {
				p := shared.PeripheralDevice{}
				if v, ok := item["Type"].(string); ok {
					p.Type = v
				}
				if v, ok := item["Description"].(string); ok {
					p.Description = v
				}
				if v, ok := item["Manufacturer"].(string); ok {
					p.Manufacturer = v
				}
				if v, ok := item["HardwareID"].(string); ok && v != "" {
					p.VendorID, p.ProductID = parseVendorProductFromHardwareID(v)
				}
				p.ConnectionType = "USB"
				p.Status = "Connected"
				if p.Description != "" {
					peripherals = append(peripherals, p)
				}
			}
		}
	}

	wmiOutput, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		`Get-WmiObject Win32_SoundDevice | Select-Object Name, Manufacturer | ConvertTo-Json -Depth 2`)
	if err == nil {
		wmiOutput = strings.TrimSpace(wmiOutput)
		if wmiOutput != "" {
			var arr []map[string]any
			var obj map[string]any
			if json.Unmarshal([]byte(wmiOutput), &arr) != nil {
				if json.Unmarshal([]byte(wmiOutput), &obj) == nil {
					arr = []map[string]any{obj}
				}
			}
			for _, item := range arr {
				p := shared.PeripheralDevice{
					Type:           "Audio Device",
					ConnectionType: "Built-in Audio",
					IsBuiltIn:      true,
					Status:         "Connected",
				}
				if v, ok := item["Name"].(string); ok {
					p.Description = v
				}
				if v, ok := item["Manufacturer"].(string); ok {
					p.Manufacturer = v
				}
				if p.Description != "" {
					peripherals = append(peripherals, p)
				}
			}
		}
	}

	return peripherals
}
