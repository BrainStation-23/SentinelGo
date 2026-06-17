package osinfo

import (
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

// Collect gathers comprehensive system information including OS, CPU, memory, disk, and network details.
func Collect() *shared.SystemInfo {
	cfg, err := config.Load("")
	if err != nil {
		cfg = &config.Config{}
	}

	hInfo, err := host.Info()
	if err != nil || hInfo == nil {
		return nil
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

	firmwareType, firmwareVendor, firmwareVersion := systempkg.GetFirmwareInfo()
	osInformation := systempkg.GetOSInformation()

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
		GPUs:             gpupkg.Get(),
		RAMs:             rampkg.Get(),
		Disks:            diskpkg.Get(),
		FirmwareType:     firmwareType,
		FirmwareVendor:   firmwareVendor,
		FirmwareVersion:  firmwareVersion,
		NetworkAdapters:  networkpkg.Get(),
		Peripherals:      peripheralspkg.Get(),
		Displays:         displaypkg.Get(),
		CPUInfoDetailed:  cpuResult.Detailed,
		AudioDevices:     audiopkg.Get(),
		Printers:         printerspkg.Get(),
		OSInformation:    osInformation,
		SecurityInfo:     securitypkg.Collect(),
	}
}
