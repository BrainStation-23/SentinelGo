package display

import "sentinelgo/internal/osinfo/shared"

func Get() []shared.Display {
	return getDisplays()
}
