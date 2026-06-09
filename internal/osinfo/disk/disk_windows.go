package disk

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getDisks() []shared.DiskDevice {
	var disks []shared.DiskDevice

	// Get-PhysicalDisk wraps MSFT_PhysicalDisk. PowerShell's Storage module already maps the
	// underlying uint16 enums to human-readable strings ("SSD", "NVMe", "Healthy", …) in its
	// object layer, so we do NOT cast MediaType/BusType/HealthStatus to [int] — those casts
	// would fail. DeviceId is a string digit ("0", "1", …) and is safe to cast to [int].
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		`Get-PhysicalDisk | ForEach-Object { [PSCustomObject]@{ DeviceId=[int]$_.DeviceId; FriendlyName=$_.FriendlyName; SerialNumber=$_.SerialNumber; MediaType=$_.MediaType; HealthStatus=$_.HealthStatus; BusType=$_.BusType; Size=$_.Size } } | ConvertTo-Json`)
	if err != nil {
		return disks
	}

	output = strings.TrimSpace(output)
	var arr []map[string]any
	var obj map[string]any
	if json.Unmarshal([]byte(output), &arr) != nil {
		if json.Unmarshal([]byte(output), &obj) == nil {
			arr = []map[string]any{obj}
		}
	}

	for _, item := range arr {
		var description, serial, mediaType, busType, healthStr string
		var totalBytes uint64
		diskIndex := -1

		if v, ok := item["DeviceId"].(float64); ok {
			diskIndex = int(v)
		}
		if v, ok := item["FriendlyName"].(string); ok {
			description = strings.TrimSpace(v)
		}
		if v, ok := item["SerialNumber"].(string); ok {
			serial = strings.TrimSpace(v)
		}
		if v, ok := item["MediaType"].(string); ok {
			mediaType = v
		}
		if v, ok := item["BusType"].(string); ok {
			busType = v
		}
		if v, ok := item["HealthStatus"].(string); ok {
			healthStr = v
		}
		if v, ok := item["Size"].(float64); ok {
			totalBytes = uint64(v)
		}

		encryptionStatus := "unknown"
		encryptionType := "unknown"
		driveLetter := ""
		fileSystem := ""
		var freeBytes uint64

		if diskIndex >= 0 {
			// Single query: drive letter, free space, filesystem, and BitLocker status.
			// ProtectionStatus cast to [int] (0=Off, 1=On). EncryptionMethod.ToString() yields
			// named enum ("XtsAes256", "HardwareEncryption", …). try/catch handles volumes
			// without BitLocker (including Windows Home).
			cmd := fmt.Sprintf(
				`Get-Partition -DiskNumber %d | Where-Object { $_.DriveLetter } | ForEach-Object { $dl = [string]$_.DriveLetter; $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${dl}:'"; try { $v = Get-BitLockerVolume -MountPoint "${dl}:" -ErrorAction Stop; [PSCustomObject]@{DriveLetter=$dl; FreeSpace=$ld.FreeSpace; FileSystem=$ld.FileSystem; ProtectionStatus=[int]$v.ProtectionStatus; EncryptionMethod=$v.EncryptionMethod.ToString()} } catch { [PSCustomObject]@{DriveLetter=$dl; FreeSpace=$ld.FreeSpace; FileSystem=$ld.FileSystem; ProtectionStatus=0; EncryptionMethod='None'} } } | Select-Object -First 1 | ConvertTo-Json`,
				diskIndex)
			if out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", cmd); err == nil {
				var result map[string]any
				if json.Unmarshal([]byte(strings.TrimSpace(out)), &result) == nil {
					if dl, ok := result["DriveLetter"].(string); ok {
						driveLetter = strings.TrimSpace(dl)
					}
					if fs, ok := result["FreeSpace"].(float64); ok {
						freeBytes = uint64(fs)
					}
					if fsys, ok := result["FileSystem"].(string); ok {
						fileSystem = strings.TrimSpace(fsys)
					}
					if ps, ok := result["ProtectionStatus"].(float64); ok {
						switch int(ps) {
						case 1: // On
							encryptionStatus = "enabled"
						case 0: // Off
							encryptionStatus = "disabled"
							encryptionType = "none"
						}
					}
					if em, ok := result["EncryptionMethod"].(string); ok && encryptionStatus == "enabled" {
						switch em {
						case "HardwareEncryption":
							encryptionType = "hardware"
						case "None", "Unspecified":
							// protection on but no active method reported
						default: // AES128, AES256, XtsAes128, XtsAes256
							encryptionType = "software"
						}
					}
				}
			}
		}

		disks = append(disks, shared.DiskDevice{
			FreeCapacity:     freeBytes,
			Description:      description,
			Type:             "Physical disk drive",
			Capacity:         totalBytes,
			EncryptionStatus: encryptionStatus,
			EncryptionType:   encryptionType,
			SerialNumber:     serial,
			Manufacturer:     manufacturerFromModel(description),
			DriveLetter:      driveLetter,
			DriveType:        windowsDriveType(mediaType, busType),
			HealthStatus:     windowsHealthStatus(healthStr),
			InterfaceType:    windowsInterfaceType(busType),
			FileSystem:       fileSystem,
		})
	}
	return disks
}

// windowsDriveType maps Get-PhysicalDisk.MediaType and BusType strings to a canonical
// drive type. PowerShell's Storage module already converts the underlying uint16 enums
// to strings ("SSD", "HDD", "NVMe", etc.) before we ever see them.
// BusType "NVMe" takes precedence over a generic "SSD" MediaType.
func windowsDriveType(mediaType, busType string) string {
	if strings.EqualFold(busType, "NVMe") {
		return "NVMe"
	}
	switch strings.ToLower(mediaType) {
	case "hdd":
		return "HDD"
	case "ssd":
		return "SSD"
	case "scm":
		return "SCM"
	default:
		return "Unknown"
	}
}

// windowsInterfaceType normalises Get-PhysicalDisk.BusType to a canonical interface name.
// BusType arrives as a string from PowerShell's Storage module ("NVMe", "SATA", etc.).
func windowsInterfaceType(busType string) string {
	switch strings.ToLower(busType) {
	case "nvme":
		return "NVMe"
	case "sata":
		return "SATA"
	case "sas":
		return "SAS"
	case "scsi":
		return "SCSI"
	case "usb":
		return "USB"
	case "ata":
		return "ATA"
	case "atapi":
		return "ATAPI"
	case "ieee1394":
		return "IEEE1394"
	case "raid":
		return "RAID"
	case "iscsi":
		return "iSCSI"
	case "sd":
		return "SD"
	case "mmc":
		return "MMC"
	case "virtual", "filebackedvirtual":
		return "Virtual"
	case "spaces":
		return "Spaces"
	case "scm":
		return "SCM"
	case "":
		return "Unknown"
	default:
		return busType
	}
}

// windowsHealthStatus normalises Get-PhysicalDisk.HealthStatus to canonical values.
func windowsHealthStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "healthy":
		return "Healthy"
	case "warning":
		return "Warning"
	case "unhealthy":
		return "Unhealthy"
	default:
		return "Unknown"
	}
}
