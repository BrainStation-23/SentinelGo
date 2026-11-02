//go:build !darwin

package mdm

import "sentinelgo/internal/osinfo/shared"

// collect has nothing to report on this platform yet.
func collect(string) *shared.MDMInfo { return nil }
