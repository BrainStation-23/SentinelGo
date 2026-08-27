//go:build darwin

package physicaldisks

import (
	"context"
	"os/exec"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
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

// smartCapability reports whether diskutil is available to answer SMART.
//
// macOS exposes far less than the other platforms: `diskutil info` reports a
// SMART *status* only, so Healthy is populated and temperature, power-on hours
// and wear are always nil. That is a reduced result within a supported
// capability, not an unsupported one — the mechanism works and answers the
// question it can answer, and the empty fields are already visible as nil.
//
// diskutil ships with every macOS release, so this lookup effectively always
// succeeds; it is written as a probe anyway so a stripped or PATH-broken host
// reports the honest answer instead of a capability claim nothing verified.
//
// Note that Apple silicon internal NVMe frequently reports no SMART status at
// all. That surfaces as a nil SMART block on those disks, which is correct:
// the host CAN be asked, and the answer is that this device does not say.
func smartCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("diskutil"); err != nil {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}
