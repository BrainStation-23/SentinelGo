//go:build windows

package peripherals

// Fuzz target for the Windows PnP / Win32_SoundDevice parsers, fed through the
// PowerShell ConvertTo-Json entry point they are used with.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Windows).
// To fuzz: go test -run='^$' -fuzz='^FuzzWindowsPeripheralParsers$' -fuzztime=1m ./internal/osinfo/peripherals/

import "testing"

func FuzzWindowsPeripheralParsers(f *testing.F) {
	for _, s := range []string{
		`[{"FriendlyName":"Logitech USB Receiver","InstanceId":"USB\\VID_046D&PID_C52B\\5&1234","Class":"HIDClass","Status":"OK"}]`,
		`{"Name":"Realtek High Definition Audio","Manufacturer":"Realtek","Status":"OK"}`,
		`[null]`, `[{}]`, `[{"FriendlyName":1,"InstanceId":["x"]}]`, `null`, `[]`, `{`, ``,
		`USB\VID_`, `USB\VID_&PID_`, `VID_046D`, `PID_C52B`, `\VID_\PID_\`,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		items := decodePowerShellJSONItems(s)
		_ = parsePnpDevices(items)
		_ = parseSoundDeviceItems(items)
		_, _ = parseVendorProductFromHardwareID(s)
	})
}
