//go:build darwin

package peripherals

// Fuzz target for the macOS ioreg HID parser. The system_profiler walkers take
// already-decoded JSON structures and are not fuzzed directly.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (macOS).
// To fuzz: go test -run='^$' -fuzz='^FuzzParseHIDDevices$' -fuzztime=1m ./internal/osinfo/peripherals/

import (
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func FuzzParseHIDDevices(f *testing.F) {
	for _, s := range []string{
		"+-o IOHIDDevice  <class IOHIDDevice>\n  | \"Product\" = \"Magic Keyboard\"\n  | \"VendorID\" = 76\n",
		"+-o IOHIDDevice\n=\n= =\n\"\" = \"\"",
		"IOHIDDevice", "=", "", strings.Repeat("+-o IOHIDDevice\n", 100),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		var peripherals []shared.PeripheralDevice
		parseHIDDevices(s, &peripherals)
	})
}
