//go:build darwin

package identity

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// appleManufacturer is a fact, not a fabrication: every genuine Mac reports
// "Apple Inc." as its manufacturer, and Apple's firmware does not expose that
// field separately from the platform name the way Win32_ComputerSystem does.
const appleManufacturer = "Apple Inc."

// platformExtra reads macOS-only identity fields via ioreg. Asset tag and
// board serial are not exposed by Apple firmware (see
// docs/telemetry/03-collection-matrix.md) and are left empty rather than
// guessed. Device UUID and machine ID both resolve to IOPlatformUUID: Apple
// does not expose a separate install-time machine identifier the way Windows'
// MachineGuid or Linux's /etc/machine-id do.
func platformExtra(_ context.Context) extra {
	ex := extra{Manufacturer: appleManufacturer}

	uuid, err := readPlatformUUID()
	if err != nil {
		ex.Warnings = append(ex.Warnings, "ioreg IOPlatformUUID read failed")
		return ex
	}
	ex.DeviceUUID = uuid
	ex.MachineID = uuid
	ex.Source = "exec:ioreg:IOPlatformUUID"
	return ex
}

// readPlatformUUID parses `ioreg -rd1 -c IOPlatformExpertDevice` output for
// IOPlatformUUID, the same mechanism internal/osinfo/system uses for the
// serial number fallback, kept here as its own call since we need this
// specific property rather than the serial number.
func readPlatformUUID() (string, error) {
	output, err := shared.RunCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	return clean(parsePlatformUUID(output)), nil
}
