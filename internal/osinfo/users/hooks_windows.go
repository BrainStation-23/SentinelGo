package users

import "sentinelgo/internal/osinfo/shared"

// The collectors reach the OS only through these, so tests can stub them.
var (
	runCommand    = shared.RunCommand
	runPowerShell = shared.RunPowerShell
)
