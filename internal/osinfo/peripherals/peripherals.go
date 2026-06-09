package peripherals

import (
	"sentinelgo/internal/osinfo/shared"
)

// Get returns the list of connected peripheral devices for the current platform.
func Get() []shared.PeripheralDevice {
	return getPeripherals()
}
