package osinfo

import (
	"context"
	"log"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"

	"sentinelgo/internal/config"
	audiopkg "sentinelgo/internal/osinfo/audio"
	cpupkg "sentinelgo/internal/osinfo/cpu"
	diskpkg "sentinelgo/internal/osinfo/disk"
	displaypkg "sentinelgo/internal/osinfo/display"
	gpupkg "sentinelgo/internal/osinfo/gpu"
	networkpkg "sentinelgo/internal/osinfo/network"
	peripheralspkg "sentinelgo/internal/osinfo/peripherals"
	printerspkg "sentinelgo/internal/osinfo/printers"
	rampkg "sentinelgo/internal/osinfo/ram"
	securitypkg "sentinelgo/internal/osinfo/security"
	"sentinelgo/internal/osinfo/shared"
	systempkg "sentinelgo/internal/osinfo/system"
	userspkg "sentinelgo/internal/osinfo/users"
)

// Collect gathers comprehensive system information including OS, CPU, memory,
// disk, and network details.
//
// It is retained unchanged for callers that genuinely have no context — the
// debug CLI commands. Anything running on a scheduler tick should use
// CollectContext so its deadline actually reaches the collectors.
func Collect() *shared.SystemInfo {
	info, _ := CollectContext(context.Background())
	return info
}

// CollectContext is Collect with cancellation.
//
// # The problem it solves
//
// Collect has no context, so the scheduler bounded it by running it in a
// goroutine and abandoning that goroutine on timeout. Abandoning a goroutine
// does not stop it: every collector still ran to completion and every
// subprocess it had spawned kept going, on top of the ones the NEXT cycle
// started. A hung collector therefore leaked a goroutine and a process tree on
// every tick, and adding subprocess-based collectors made it worse.
//
// # What cancellation actually reaches
//
// Two different degrees, and the difference is worth stating plainly rather
// than implying the stronger one everywhere:
//
//   - security is fully context-aware: its subprocesses are killed when ctx is
//     done. It is migrated first because it dominates the cycle — roughly 20
//     PowerShell invocations at 350–900 ms cold on Windows.
//   - every other collector is GATED, not interrupted: ctx is checked before
//     each one starts, so cancellation stops the cycle from starting further
//     work, but a collector already running finishes. Each is separately bounded
//     by the 30-second timeout inside shared.RunCommand, so the worst case is
//     one in-flight subprocess outliving the deadline by up to that long —
//     against the previous behaviour of every remaining collector running.
//
// Migrating the rest is tracked in docs/telemetry/06-existing-code-observations.md
// item 4; each one is a change to a working collector on three platforms and is
// deliberately incremental.
//
// On cancellation it returns (nil, ctx.Err()): a partially-filled SystemInfo
// would be fingerprinted and uploaded as though it were the machine's real
// state, which would report hardware as having disappeared.
func CollectContext(ctx context.Context) (*shared.SystemInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cfg, err := config.Load("")
	if err != nil {
		cfg = &config.Config{}
	}

	hInfo, err := host.Info()
	if err != nil || hInfo == nil {
		return nil, nil
	}

	cpuResult := cpupkg.Get()

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("osinfo: failed to read memory info: %v", err)
	}
	diskInfo, err := disk.Usage("/")
	if err != nil {
		log.Printf("osinfo: failed to read disk usage for /: %v", err)
	}
	netInfo, err := psnet.IOCounters(true)
	if err != nil {
		log.Printf("osinfo: failed to read network counters: %v", err)
	}
	netInterfaces, err := psnet.Interfaces()
	if err != nil {
		log.Printf("osinfo: failed to read network interfaces: %v", err)
	}

	var netStats []shared.NetInfo
	for _, ni := range netInfo {
		var macAddr string
		for _, iface := range netInterfaces {
			if iface.Name == ni.Name {
				macAddr = iface.HardwareAddr
				break
			}
		}
		netStats = append(netStats, shared.NetInfo{
			Name:      ni.Name,
			BytesSent: ni.BytesSent,
			BytesRecv: ni.BytesRecv,
			MACAddr:   macAddr,
		})
	}

	var memStats shared.MemoryInfo
	if memInfo != nil {
		memStats = shared.MemoryInfo{
			Total: memInfo.Total,
			Used:  memInfo.Used,
			Free:  memInfo.Free,
			Usage: memInfo.UsedPercent,
		}
	}
	var diskStats shared.DiskInfo
	if diskInfo != nil {
		diskStats = shared.DiskInfo{
			Total: diskInfo.Total,
			Used:  diskInfo.Used,
			Free:  diskInfo.Free,
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	firmwareType, firmwareVendor, firmwareVersion := systempkg.GetFirmwareInfo()
	osInformation := systempkg.GetOSInformation()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The expensive collectors, each preceded by a cancellation check so an
	// expired deadline stops the cycle here instead of paying for all of them.
	// securityInfo is the only one that also cancels its own subprocesses.
	disks := diskpkg.Get()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	gpus := gpupkg.Get()
	displays := displaypkg.Get()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peripherals := peripheralspkg.Get()
	printers := printerspkg.Get()
	audioDevices := audiopkg.Get()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	securityInfo := securitypkg.CollectContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &shared.SystemInfo{
		Timestamp:        time.Now().UTC(),
		Hostname:         hInfo.Hostname,
		Uptime:           hInfo.Uptime,
		CPU:              cpuResult.Info,
		Memory:           memStats,
		Disk:             diskStats,
		Network:          netStats,
		MACAddress:       networkpkg.GetPrimaryMACAddress(netInterfaces),
		SerialNumber:     systempkg.GetSerialNumber(),
		HardwareModel:    systempkg.GetHardwareModel(),
		OSQueryVersion:   systempkg.GetOSQueryVersion(),
		BatteryCondition: systempkg.GetBatteryCondition(),
		LocalUsers:       userspkg.Get(),
		AgentVersion:     cfg.CurrentVersion,
		FQDN:             systempkg.GetFQDN(),
		ChassisType:      systempkg.GetChassisType(),
		KernelVersion:    osInformation.OSVersion,
		GPUs:             gpus,
		RAMs:             rampkg.Get(),
		Disks:            disks,
		FirmwareType:     firmwareType,
		FirmwareVendor:   firmwareVendor,
		FirmwareVersion:  firmwareVersion,
		TPMVersion:       systempkg.GetTPMVersion(),
		NetworkAdapters:  networkpkg.Get(),
		Peripherals:      peripherals,
		Displays:         displays,
		CPUInfoDetailed:  cpuResult.Detailed,
		AudioDevices:     audioDevices,
		Printers:         printers,
		OSInformation:    osInformation,
		SecurityInfo:     securityInfo,
	}, nil
}
