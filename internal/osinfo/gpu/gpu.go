package gpu

import "sentinelgo/internal/osinfo/shared"

// Get returns GPU information for the current platform.
func Get() []shared.GPU {
	return getGPUs()
}
