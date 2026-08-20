//go:build linux

package physicaldisks

import (
	"context"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
)

// platformDisks enumerates disks via lsblk (one call for every disk, per the
// matrix doc's "one subprocess for many items" rule) and, when smartctl is
// installed, adds a per-disk SMART summary from its structured JSON output.
func platformDisks(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "lsblk", "--json", "-d", "-b", "-o", "NAME,TYPE,MODEL,SERIAL,SIZE,ROTA,TRAN")
	if err != nil {
		return signal{Warnings: []string{"lsblk failed to run"}, Err: err}
	}

	rows, parseErr := parseLsblkDisks(out)
	if parseErr != nil {
		return signal{Warnings: []string{"lsblk returned unparseable JSON"}, Err: parseErr}
	}

	hasSmartctl := false
	if _, lookErr := exec.LookPath("smartctl"); lookErr == nil {
		hasSmartctl = true
	}

	var warnings []string
	disks := make([]Disk, 0, len(rows))
	for _, row := range rows {
		d := row.toDisk()
		if hasSmartctl {
			if smart, warn := smartForDevice(ctx, d.ID); warn != "" {
				warnings = append(warnings, warn)
			} else {
				d.SMART = smart
			}
		}
		disks = append(disks, d)
	}

	source := "exec:lsblk"
	if hasSmartctl {
		source += ", exec:smartctl"
	}
	return signal{Disks: disks, Source: source, Warnings: warnings}
}

// smartForDevice runs smartctl for one device. -n standby avoids spinning up
// a sleeping drive just to read its attributes, per the matrix doc's explicit
// caution; a non-zero exit is expected and meaningful (smartctl signals drive
// health through exit-code bit flags), so RunCommandOutputContext is used
// rather than RunCommandContext, which would discard the JSON on exactly the
// failing drives that matter most.
func smartForDevice(ctx context.Context, name string) (*SMART, string) {
	out, _, err := shared.RunCommandOutputContext(ctx, "smartctl", "-n", "standby", "--json=c", "-a", "/dev/"+name)
	if err != nil {
		return nil, "smartctl failed to run for /dev/" + name
	}
	result, parseErr := parseSmartctlJSON(out)
	if parseErr != nil {
		return nil, "smartctl returned unparseable JSON for /dev/" + name
	}
	return smartFromSmartctl(result), ""
}
