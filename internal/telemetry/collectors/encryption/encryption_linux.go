//go:build linux

package encryption

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported unconditionally: lsblk is part of
// util-linux, present on every mainstream distribution.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformVolumes scans the lsblk device tree for LUKS containers. Reading
// crypto_LUKS fstype directly avoids invoking cryptsetup luksDump, which the
// matrix doc reserves for header-only inspection, not routine enumeration.
func platformVolumes(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT", "--json")
	if err != nil {
		return signal{Warnings: []string{"lsblk failed to run"}, Err: err}
	}

	volumes, parseErr := parseLinuxLUKS(out)
	if parseErr != nil {
		return signal{Warnings: []string{"lsblk returned unparseable JSON"}, Err: parseErr}
	}

	return signal{Volumes: volumes, Source: "exec:lsblk"}
}
