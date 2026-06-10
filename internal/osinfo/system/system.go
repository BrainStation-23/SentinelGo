package system

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"sentinelgo/internal/osinfo/shared"
)

// GetConfigDir returns the platform-specific config directory.
// Has a default: case so it remains in the cross-platform file.
func GetConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\SentinelGo\.sentinelgo`
	case "linux", "darwin":
		return `/opt/sentinelgo/.sentinelgo`
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "/opt/sentinelgo/.sentinelgo"
		}
		return filepath.Join(home, ".sentinelgo")
	}
}

// GetOSQueryVersion detects the installed osquery version.
func GetOSQueryVersion() string {
	cmdName := "osqueryi"
	if runtime.GOOS == "windows" {
		cmdName = "osqueryi.exe"
	}
	if output, err := shared.RunCommand(cmdName, "--version"); err == nil {
		if v := parseOSQueryVersion(output); v != "" {
			return v
		}
	}
	return "not installed"
}

// Exported wrappers — platform implementations live in the OS-specific files.
func GetSerialNumber() string                   { return getSerialNumber() }
func GetHardwareModel() string                  { return getHardwareModel() }
func GetBatteryCondition() string               { return getBatteryCondition() }
func GetFQDN() string                           { return getFQDN() }
func GetChassisType() string                    { return getChassisType() }
func GetTPMVersion() string                     { return getTPMVersion() }
func GetFirmwareInfo() (string, string, string) { return getFirmwareInfo() }
func GetOSInformation() shared.OSInformation    { return getOSInformation() }

// osInfoBase fills the fields that don't vary by OS: arch, platform, timezone, boot time.
func osInfoBase() shared.OSInformation {
	var osInfo shared.OSInformation

	arch := "32-bit"
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		arch = "64-bit"
	}
	osInfo.Architecture = arch
	osInfo.OSPlatform = runtime.GOOS

	tz, tzOffsetSecs := time.Now().Zone()
	osInfo.OSTimeZone = tz
	osInfo.OSTimeZoneOffsetMinutes = tzOffsetSecs / 60

	var bootTime time.Time
	if hInfo, err := host.Info(); err == nil && hInfo.BootTime > 0 {
		if hInfo.BootTime <= uint64(^uint64(0)>>1) {
			bootTime = time.Unix(int64(hInfo.BootTime), 0)
		}
	}
	if !bootTime.IsZero() {
		duration := time.Since(bootTime)
		osInfo.OSLastBootTime = shared.OSLastBootTime{
			Relative: parseBootRelative(duration),
			DateTime: bootTime.UTC().Format(time.RFC3339),
		}
	}

	return osInfo
}
