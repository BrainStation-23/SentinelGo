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
	output, err := shared.RunPowerShell(
		`Get-PhysicalDisk | ForEach-Object { [PSCustomObject]@{ DeviceId=[int]$_.DeviceId; FriendlyName=$_.FriendlyName; SerialNumber=$_.SerialNumber; MediaType=$_.MediaType; HealthStatus=$_.HealthStatus; BusType=$_.BusType; Size=$_.Size } } | ConvertTo-Json`)
	if err != nil {
		return disks
	}

	for _, item := range parsePhysicalDisksJSON(strings.TrimSpace(output)) {
		info := parsePhysicalDiskItem(item)
		vol := windowsVolumeInfoForDisk(info.diskIndex)
		disks = append(disks, buildWindowsDiskDevice(info, vol))
	}
	return disks
}

// parsePhysicalDisksJSON unmarshals Get-PhysicalDisk's ConvertTo-Json output. PowerShell
// emits a single object (not an array) when there's exactly one disk, so that shape is
// normalized into a one-element slice.
func parsePhysicalDisksJSON(output string) []map[string]any {
	var arr []map[string]any
	var obj map[string]any
	if json.Unmarshal([]byte(output), &arr) != nil {
		if json.Unmarshal([]byte(output), &obj) == nil {
			arr = []map[string]any{obj}
		}
	}
	return arr
}

// physicalDiskInfo bundles the fields parsed from one Get-PhysicalDisk JSON entry.
type physicalDiskInfo struct {
	diskIndex   int
	description string
	serial      string
	mediaType   string
	busType     string
	healthStr   string
	totalBytes  uint64
}

// parsePhysicalDiskItem extracts the fields SentinelGo needs from one Get-PhysicalDisk
// JSON entry. diskIndex defaults to -1 when DeviceId is absent or not numeric.
func parsePhysicalDiskItem(item map[string]any) physicalDiskInfo {
	info := physicalDiskInfo{diskIndex: -1}
	if v, ok := item["DeviceId"].(float64); ok {
		if idx, ok := shared.JSONInt(v); ok && idx >= 0 {
			info.diskIndex = idx
		}
	}
	if v, ok := item["FriendlyName"].(string); ok {
		info.description = strings.TrimSpace(v)
	}
	if v, ok := item["SerialNumber"].(string); ok {
		info.serial = strings.TrimSpace(v)
	}
	if v, ok := item["MediaType"].(string); ok {
		info.mediaType = v
	}
	if v, ok := item["BusType"].(string); ok {
		info.busType = v
	}
	if v, ok := item["HealthStatus"].(string); ok {
		info.healthStr = v
	}
	if v, ok := item["Size"].(float64); ok {
		info.totalBytes, _ = shared.JSONUint64(v)
	}
	return info
}

// windowsVolumeInfo bundles the drive-letter/filesystem/free-space/BitLocker details
// queried per-disk via Get-Partition + Get-BitLockerVolume.
type windowsVolumeInfo struct {
	driveLetter      string
	fileSystem       string
	freeBytes        uint64
	encryptionStatus string
	encryptionType   string
}

// windowsVolumeInfoForDisk queries the drive letter, free space, filesystem, and
// BitLocker status of diskIndex's first mounted partition. Returns the unknown/zero
// defaults when the disk has no mounted partition or the query fails.
func windowsVolumeInfoForDisk(diskIndex int) windowsVolumeInfo {
	vol := windowsVolumeInfo{encryptionStatus: "unknown", encryptionType: "unknown"}
	if diskIndex < 0 {
		return vol
	}

	out, err := shared.RunPowerShell(bitLockerQueryCmd(diskIndex))
	if err != nil {
		return vol
	}
	var result map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &result) != nil {
		return vol
	}
	return parseBitLockerResult(result)
}

// bitLockerQueryCmd builds the single PowerShell query for drive letter, free space,
// filesystem, and BitLocker status of diskIndex's first mounted partition.
// ProtectionStatus cast to [int] (0=Off, 1=On). EncryptionMethod.ToString() yields
// named enum ("XtsAes256", "HardwareEncryption", …). try/catch handles volumes
// without BitLocker (including Windows Home).
func bitLockerQueryCmd(diskIndex int) string {
	return fmt.Sprintf(
		`Get-Partition -DiskNumber %d | Where-Object { $_.DriveLetter } | ForEach-Object { $dl = [string]$_.DriveLetter; $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${dl}:'"; try { $v = Get-BitLockerVolume -MountPoint "${dl}:" -ErrorAction Stop; [PSCustomObject]@{DriveLetter=$dl; FreeSpace=$ld.FreeSpace; FileSystem=$ld.FileSystem; ProtectionStatus=[int]$v.ProtectionStatus; EncryptionMethod=$v.EncryptionMethod.ToString()} } catch { [PSCustomObject]@{DriveLetter=$dl; FreeSpace=$ld.FreeSpace; FileSystem=$ld.FileSystem; ProtectionStatus=0; EncryptionMethod='None'} } } | Select-Object -First 1 | ConvertTo-Json`,
		diskIndex)
}

// parseBitLockerResult extracts drive letter, free space, filesystem, and encryption
// status/type from one Get-BitLockerVolume-derived JSON result.
func parseBitLockerResult(result map[string]any) windowsVolumeInfo {
	vol := windowsVolumeInfo{encryptionStatus: "unknown", encryptionType: "unknown"}
	if dl, ok := result["DriveLetter"].(string); ok {
		vol.driveLetter = strings.TrimSpace(dl)
	}
	if fs, ok := result["FreeSpace"].(float64); ok {
		vol.freeBytes, _ = shared.JSONUint64(fs)
	}
	if fsys, ok := result["FileSystem"].(string); ok {
		vol.fileSystem = strings.TrimSpace(fsys)
	}
	vol.encryptionStatus, vol.encryptionType = classifyBitLockerProtection(result)
	if em, ok := result["EncryptionMethod"].(string); ok && vol.encryptionStatus == "enabled" {
		vol.encryptionType = classifyBitLockerMethod(em, vol.encryptionType)
	}
	return vol
}

// classifyBitLockerProtection maps ProtectionStatus (0=Off, 1=On) to a canonical
// encryption status/type pair. Both stay "unknown" when the field is missing or
// holds a value other than 0/1.
func classifyBitLockerProtection(result map[string]any) (status, encType string) {
	status, encType = "unknown", "unknown"
	ps, ok := result["ProtectionStatus"].(float64)
	if !ok {
		return status, encType
	}
	psInt, ok := shared.JSONInt(ps)
	if !ok {
		return status, encType
	}
	switch psInt {
	case 1: // On
		status = "enabled"
	case 0: // Off
		status = "disabled"
		encType = "none"
	}
	return status, encType
}

// classifyBitLockerMethod maps BitLocker's EncryptionMethod enum string to a canonical
// encryption type, given protection is already known to be enabled. current is
// returned unchanged when protection is on but no active method is reported.
func classifyBitLockerMethod(em, current string) string {
	switch em {
	case "HardwareEncryption":
		return "hardware"
	case "None", "Unspecified":
		return current // protection on but no active method reported
	default: // AES128, AES256, XtsAes128, XtsAes256
		return "software"
	}
}

// buildWindowsDiskDevice assembles a shared.DiskDevice from one Get-PhysicalDisk entry
// and its associated volume/BitLocker details.
func buildWindowsDiskDevice(info physicalDiskInfo, vol windowsVolumeInfo) shared.DiskDevice {
	return shared.DiskDevice{
		FreeCapacity:     vol.freeBytes,
		Description:      info.description,
		Type:             "Physical disk drive",
		Capacity:         info.totalBytes,
		EncryptionStatus: vol.encryptionStatus,
		EncryptionType:   vol.encryptionType,
		SerialNumber:     info.serial,
		Manufacturer:     manufacturerFromModel(info.description),
		DriveLetter:      vol.driveLetter,
		DriveType:        windowsDriveType(info.mediaType, info.busType),
		HealthStatus:     windowsHealthStatus(info.healthStr),
		InterfaceType:    windowsInterfaceType(info.busType),
		FileSystem:       vol.fileSystem,
	}
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
