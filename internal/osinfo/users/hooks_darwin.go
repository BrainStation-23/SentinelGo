package users

import "sentinelgo/internal/osinfo/shared"

// The collectors reach the OS only through this, so tests can stub it.
var runCommand = shared.RunCommand
