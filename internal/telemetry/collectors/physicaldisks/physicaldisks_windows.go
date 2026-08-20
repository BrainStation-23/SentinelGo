//go:build windows

package physicaldisks

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// diskScript combines Get-PhysicalDisk with Get-StorageReliabilityCounter in
// one PowerShell call rather than one call per disk — a Get-PhysicalDisk +
// Get-StorageReliabilityCounter pipeline is the mechanism
// docs/telemetry/03-collection-matrix.md recommends precisely because it is
// structured, native cmdlet output rather than a byte blob to decode.
const diskScript = `Get-PhysicalDisk | ForEach-Object {
	$d = $_
	$r = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
	[PSCustomObject]@{
		Id = ''+$d.DeviceId
		Model = ''+$d.FriendlyName
		Serial = ''+$d.SerialNumber
		Size = $d.Size
		MediaType = ''+$d.MediaType.ToString()
		BusType = ''+$d.BusType.ToString()
		Health = ''+$d.HealthStatus.ToString()
		Temperature = $r.Temperature
		PowerOnHours = $r.PowerOnHours
		Wear = $r.Wear
	}
} | ConvertTo-Json -Compress`

// platformDisks runs the combined disk+reliability-counter script.
func platformDisks(_ context.Context) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", diskScript)
	if err != nil {
		return signal{Warnings: []string{"Get-PhysicalDisk query failed"}, Err: err}
	}

	rows, parseErr := parseWindowsDisks(out)
	if parseErr != nil {
		return signal{
			Warnings: []string{"Get-PhysicalDisk returned unparseable JSON"},
			Err:      parseErr,
		}
	}

	disks := make([]Disk, 0, len(rows))
	for _, r := range rows {
		disks = append(disks, r.toDisk())
	}

	// ", " rather than "+": a "+"-joined single token here is long enough,
	// and drawn entirely from the token/key character class, to trip
	// SanitizeMessage's secret-shaped-token redaction — turning this
	// harmless diagnostic string into "<redacted>" in every log and
	// CollectorResult. ", " keeps the two cmdlet names as separate,
	// sub-32-character tokens.
	return signal{Disks: disks, Source: "powershell:Get-PhysicalDisk, Get-StorageReliabilityCounter"}
}
