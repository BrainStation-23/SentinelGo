//go:build darwin

package encryption

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported unconditionally: fdesetup ships
// standard on every supported macOS target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformVolumes reads FileVault status via `fdesetup status`. FileVault
// applies to the whole boot volume on modern macOS (APFS), so this reports
// one entry for "/" rather than enumerating every mounted volume.
func platformVolumes(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "fdesetup", "status")
	if err != nil {
		return signal{Warnings: []string{"fdesetup status failed to run"}, Err: err}
	}

	status := parseFdesetupStatus(out)
	volume := Volume{
		MountPoint:       "/",
		EncryptionType:   "filevault",
		ProtectionStatus: status,
	}
	if status == "off" {
		volume.EncryptionType = "none"
	}

	return signal{Volumes: []Volume{volume}, Source: "exec:fdesetup"}
}
