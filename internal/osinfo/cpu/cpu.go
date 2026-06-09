package cpu

import "sentinelgo/internal/osinfo/shared"

// Result holds both the summary and detailed CPU information for the current platform.
type Result struct {
	Info     shared.CPUInfo
	Detailed shared.CPUInfoDetailed
}

// Get returns CPU information for the current platform.
func Get() Result {
	return collect()
}
