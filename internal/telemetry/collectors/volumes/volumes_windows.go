//go:build windows

package volumes

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// volumeScript filters to volumes with an assigned drive letter, skipping
// EFI/recovery/System-Reserved partitions that are not what an operator
// means by "a drive on this machine" — the lightweight P0 scope this
// collector targets, not a full partition-table dump.
const volumeScript = `Get-Volume | Where-Object { $_.DriveLetter } | ` +
	`Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining | ConvertTo-Json -Compress`

func platformVolumes(_ context.Context) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", volumeScript)
	if err != nil {
		return signal{Warnings: []string{"Get-Volume query failed"}, Err: err}
	}

	rows, parseErr := parseWindowsVolumes(out)
	if parseErr != nil {
		return signal{Warnings: []string{"Get-Volume returned unparseable JSON"}, Err: parseErr}
	}

	volumes := make([]Volume, 0, len(rows))
	for _, r := range rows {
		volumes = append(volumes, r.toVolume())
	}

	return signal{Volumes: volumes, Source: "powershell:Get-Volume"}
}
