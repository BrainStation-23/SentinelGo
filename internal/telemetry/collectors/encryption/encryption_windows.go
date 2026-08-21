//go:build windows

package encryption

import (
	"context"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// bitlockerVolumeScript reports MountPoint, ProtectionStatus,
// EncryptionPercentage, and a flattened list of key protector type names —
// the exact fields the matrix doc calls out (ProtectionStatus,
// EncryptionPercentage, EncryptionMethod, key protector types).
//
// $ErrorActionPreference = 'Stop' plus the try/catch is load-bearing, not
// decoration: the BitLocker module's underlying Get-CimInstance call signals
// "access denied" (confirmed by hand: this cmdlet requires elevation and
// fails when the agent is not running with sufficient rights) via a
// NON-terminating Write-Error, which by default leaves the script's exit
// code at 0. shared.RunCommand only inspects the exit code and stdout — it
// cannot see that non-terminating error at all — so without forcing it
// terminating here, a permission failure would silently produce empty stdout
// and be reported as "success, zero encrypted volumes" instead of a genuine
// failure. This is exactly the silently-wrong-answer class of bug the
// directory collector's review caught for a different mechanism.
const bitlockerVolumeScript = `$ErrorActionPreference = 'Stop'
try {
	Get-BitLockerVolume | ForEach-Object {
		[PSCustomObject]@{
			MountPoint = ''+$_.MountPoint
			ProtectionStatus = ''+$_.ProtectionStatus.ToString()
			EncryptionPercentage = $_.EncryptionPercentage
			KeyProtectorTypes = @($_.KeyProtector | ForEach-Object { ''+$_.KeyProtectorType.ToString() })
		}
	} | ConvertTo-Json -Compress -Depth 4
} catch {
	exit 1
}`

// platformCapability checks whether the BitLocker PowerShell module is
// present: it ships with Pro/Enterprise/Education editions but not Home, so
// this is a real, worth-checking gate rather than an always-true one.
func platformCapability(_ context.Context) tel.CapabilityState {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
	if err != nil || strings.TrimSpace(out) != "yes" {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

func platformVolumes(_ context.Context) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", bitlockerVolumeScript)
	if err != nil {
		return signal{Warnings: []string{"Get-BitLockerVolume query failed"}, Err: err}
	}

	rows, parseErr := parseWindowsVolumes(out)
	if parseErr != nil {
		return signal{Warnings: []string{"Get-BitLockerVolume returned unparseable JSON"}, Err: parseErr}
	}

	volumes := make([]Volume, 0, len(rows))
	for _, r := range rows {
		volumes = append(volumes, r.toVolume())
	}

	return signal{Volumes: volumes, Source: "powershell:Get-BitLockerVolume"}
}
