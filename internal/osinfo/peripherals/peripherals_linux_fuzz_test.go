//go:build linux

package peripherals

// Fuzz target for the Linux peripheral parsers (/proc/bus/input/devices,
// lsusb, aplay -l, bluetoothctl, lspci). One target feeds the same input to
// every parser to keep the nightly fuzz matrix small.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Linux).
// To fuzz: go test -run='^$' -fuzz='^FuzzLinuxPeripheralParsers$' -fuzztime=1m ./internal/osinfo/peripherals/

import (
	"strings"
	"testing"
)

func FuzzLinuxPeripheralParsers(f *testing.F) {
	for _, s := range []string{
		sampleInputDevices,
		"Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver",
		"Bus 001 Device 002: ID",
		"Bus 001 Device 002: ID 046d",
		"card 0: PCH [HDA Intel PCH], device 0: ALC3246 Analog [ALC3246 Analog]",
		"card 0:",
		"card",
		"Device AA:BB:CC:DD:EE:FF My Headphones",
		"Device",
		"00:1f.3 Audio device [0403]: Intel Corporation Device [8086:51c8] (rev 01)",
		"00:1f.3 Audio device",
		"I: Bus=0003 Vendor=046d Product=c52b Version=0111\nN: Name=\"Logitech\"\n\n",
		"N: Name=\"",
		"",
		strings.Repeat("I: Bus=\n", 200),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		_ = parseInputDevices(s)
		_ = parseLsusbOutput(s)
		_ = parseAplayOutput(s)
		_ = parseLspciAudioOutput(s)
		for _, line := range strings.Split(s, "\n") {
			_, _ = parseBluetoothctlLine(line)
		}
	})
}
