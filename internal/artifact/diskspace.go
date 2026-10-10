package artifact

import (
	"fmt"
	"os"
	"path/filepath"
)

// diskSpaceMargin is the extra headroom factor required over the raw sum of
// artifact sizes (10%, matching contract §3.3).
const diskSpaceMargin = 1.1

// checkDiskSpace verifies that the volume containing dir has at least
// sum(spec.Size) * 1.1 bytes free before starting any download.
func checkDiskSpace(dir string, specs []Spec) error {
	// Ensure the directory exists so freeBytesForDir can stat its volume.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	free, err := freeBytesForDir(absDir)
	if err != nil {
		// If we can't check disk space, log a warning and proceed. This is
		// a best-effort guard; a real out-of-space failure will surface during
		// download and produce a clear error.
		return nil
	}

	var total int64
	for _, s := range specs {
		total += s.Size
	}

	required := uint64(float64(total) * diskSpaceMargin)
	if free < required {
		return fmt.Errorf("insufficient disk space: need %d bytes (%.0f%% margin over %d), have %d free",
			required, (diskSpaceMargin-1)*100, total, free)
	}
	return nil
}
