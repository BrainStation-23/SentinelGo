package cpu

import (
	"fmt"
	"runtime"
	"time"

	gocpu "github.com/shirou/gopsutil/v4/cpu"

	"sentinelgo/internal/osinfo/shared"
)

func collect() Result {
	info, _ := gocpu.Info()
	percent, _ := gocpu.Percent(time.Second, false)
	physicalCores, _ := gocpu.Counts(false)
	logicalCores, _ := gocpu.Counts(true)

	var modelName, clockSpeed, manufacturer string

	if len(info) > 0 {
		modelName = info[0].ModelName
		manufacturer = info[0].VendorID
		if info[0].Mhz > 0 {
			clockSpeed = fmt.Sprintf("%.0f MHz", info[0].Mhz)
		}
	}

	var usage float64
	if len(percent) > 0 {
		usage = percent[0]
	}

	return Result{
		Info: shared.CPUInfo{
			ModelName: modelName,
			Cores:     logicalCores,
			Usage:     usage,
		},
		Detailed: shared.CPUInfoDetailed{
			Processor:          modelName,
			ClockSpeed:         clockSpeed,
			NumberCores:        physicalCores,
			NumberLogicalCores: logicalCores,
			ArchitectureType:   runtime.GOARCH,
			Manufacturer:       manufacturer,
		},
	}
}
