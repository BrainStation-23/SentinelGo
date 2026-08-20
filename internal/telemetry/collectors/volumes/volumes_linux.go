//go:build linux

package volumes

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// pseudoFilesystems are excluded via df's own -x flag so the volume list
// reports real, disk-backed filesystems rather than every virtual mount a
// modern Linux system accumulates (proc, sysfs, cgroups, container overlays).
var pseudoFilesystems = []string{"tmpfs", "devtmpfs", "proc", "sysfs", "squashfs", "overlay", "cgroup", "cgroup2"}

func platformVolumes(ctx context.Context) signal {
	args := []string{"--block-size=1", "--output=target,fstype,size,avail"}
	for _, fs := range pseudoFilesystems {
		args = append(args, "-x", fs)
	}

	out, _, err := shared.RunCommandOutputContext(ctx, "df", args...)
	if err != nil {
		return signal{Warnings: []string{"df failed to run"}, Err: err}
	}

	volumes := parseLinuxDF(out)
	if volumes == nil {
		return signal{
			Warnings: []string{"df produced no parseable volume rows"},
			Err:      tel.ErrEmptyOutput,
		}
	}

	return signal{Volumes: volumes, Source: "exec:df"}
}
