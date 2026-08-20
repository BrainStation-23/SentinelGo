//go:build linux

package identity

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// platformExtra reads Linux-only identity fields from sysfs DMI tables and
// /etc/machine-id, per docs/telemetry/03-collection-matrix.md. product_uuid
// and board_serial are typically root-only; the agent runs as root/SYSTEM so
// this is expected to succeed, and a permission failure degrades to an empty
// field rather than an error.
func platformExtra(_ context.Context) extra {
	var ex extra
	var found bool

	if v, err := shared.ReadFileContent("/sys/class/dmi/id/sys_vendor"); err == nil {
		if c := clean(v); c != "" {
			ex.Manufacturer = c
			found = true
		}
	} else {
		ex.Warnings = append(ex.Warnings, "sys_vendor unreadable")
	}

	if v, err := shared.ReadFileContent("/sys/class/dmi/id/chassis_asset_tag"); err == nil {
		if c := clean(v); c != "" {
			ex.AssetTag = c
			found = true
		}
	}

	if v, err := shared.ReadFileContent("/sys/class/dmi/id/product_uuid"); err == nil {
		if c := clean(v); c != "" {
			ex.DeviceUUID = c
			found = true
		}
	} else {
		ex.Warnings = append(ex.Warnings, "product_uuid unreadable (requires root)")
	}

	if v, err := shared.ReadFileContent("/sys/class/dmi/id/board_serial"); err == nil {
		if c := clean(v); c != "" {
			ex.BoardSerial = c
			found = true
		}
	}

	if v, err := shared.ReadFileContent("/etc/machine-id"); err == nil {
		if c := clean(v); c != "" {
			ex.MachineID = c
			found = true
		}
	} else {
		ex.Warnings = append(ex.Warnings, "/etc/machine-id unreadable")
	}

	if found {
		ex.Source = "sysfs:/sys/class/dmi/id"
	}
	return ex
}
