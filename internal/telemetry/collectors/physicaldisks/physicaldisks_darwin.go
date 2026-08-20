//go:build darwin

package physicaldisks

import (
	"context"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// platformDisks enumerates physical disks via `diskutil list`, then reads
// each one's details via `diskutil info`. Plain (non-plist) output is used
// throughout: parsing its "Key:   Value" lines reuses the same technique
// already proven for dsregcmd/dsconfigad, and avoids adding a plist-decoding
// dependency this module does not otherwise need.
func platformDisks(ctx context.Context) signal {
	listOut, err := shared.RunCommandContext(ctx, "diskutil", "list")
	if err != nil {
		return signal{Warnings: []string{"diskutil list failed to run"}, Err: err}
	}

	ids := parseDiskutilListPhysical(listOut)

	var warnings []string
	disks := make([]Disk, 0, len(ids))
	for _, id := range ids {
		d, warn := diskFromDiskutilInfo(ctx, id)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		disks = append(disks, d)
	}

	return signal{Disks: disks, Source: "exec:diskutil", Warnings: warnings}
}

func diskFromDiskutilInfo(ctx context.Context, id string) (Disk, string) {
	out, err := shared.RunCommandContext(ctx, "diskutil", "info", id)
	if err != nil {
		return Disk{}, "diskutil info failed for " + id
	}

	info := parseDiskutilInfo(out)
	d := Disk{
		ID:           id,
		Model:        info["device / media name"],
		SizeBytes:    parseDarwinDiskSizeBytes(info["disk size"]),
		HealthStatus: info["smart status"],
	}
	if strings.EqualFold(info["solid state"], "yes") {
		d.MediaType = "ssd"
	} else if info["solid state"] != "" {
		d.MediaType = "hdd"
	}
	if protocol := info["protocol"]; protocol != "" {
		d.BusType = normalizeBusType(protocol)
	}
	if smart := info["smart status"]; smart != "" {
		healthy := strings.EqualFold(smart, "verified")
		d.SMART = &SMART{Healthy: &healthy}
	}
	return d, ""
}
