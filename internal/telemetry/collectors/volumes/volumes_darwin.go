//go:build darwin

package volumes

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformVolumes uses `df -k`, the one call BSD df offers that reports every
// mounted filesystem's size in a fixed unit; see parseDarwinDF's doc comment
// for how the variable column layout across macOS versions is handled.
//
// Filesystem type and volume label are not populated here: BSD df's default
// output does not include either, and adding a per-volume `diskutil info`
// call to recover them is deferred as unnecessary weight for this
// lightweight P0 pass.
func platformVolumes(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "df", "-k")
	if err != nil {
		return signal{Warnings: []string{"df failed to run"}, Err: err}
	}

	volumes := parseDarwinDF(out)
	if volumes == nil {
		return signal{
			Warnings: []string{"df produced no parseable volume rows"},
			Err:      tel.ErrEmptyOutput,
		}
	}

	return signal{Volumes: volumes, Source: "exec:df"}
}
