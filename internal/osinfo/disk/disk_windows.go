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
		parts := windowsPartitionsForDisk(info.diskIndex)
		disks = append(disks, buildWindowsDiskDevice(info, parts))
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

// windowsPartitionQuery lists every partition on one disk, lettered or not, with
// its volume details and BitLocker status. Get-BitLockerVolume runs once and is
// matched to partitions by access path (BitLocker reports "C:" for lettered
// volumes and \\?\Volume{guid}\ for the rest). BitLockerAvailable is false when
// the cmdlet is missing (Windows Home) or fails, so the parser can report
// "unknown" instead of "none". Only each key protector's id and type are
// selected: the RecoveryPassword property must never reach the payload.
// Get-Partition's DriveLetter is a [char] that is NUL when unset, hence the
// letter check.
const windowsPartitionQuery = `$ErrorActionPreference='SilentlyContinue'; $bl=@{}; $blOk=$false; ` +
	`try { Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { $bl[([string]$_.MountPoint).TrimEnd('\').ToUpperInvariant()]=$_ }; $blOk=$true } catch {}; ` +
	`$rows=@(Get-Partition -DiskNumber %d -ErrorAction Stop | ForEach-Object { $p=$_; ` +
	`$paths=@($p.AccessPaths | Where-Object { $_ } | ForEach-Object { [string]$_ }); ` +
	`$dl=''; if ([string]$p.DriveLetter -match '^[A-Za-z]$') { $dl=([string]$p.DriveLetter).ToUpperInvariant() }; ` +
	`$v=$p | Get-Volume -ErrorAction SilentlyContinue; ` +
	`$b=$null; foreach ($ap in $paths) { $k=$ap.TrimEnd('\').ToUpperInvariant(); if ($bl.ContainsKey($k)) { $b=$bl[$k]; break } }; ` +
	`$r=[ordered]@{PartitionNumber=[int]$p.PartitionNumber; Type=[string]$p.Type; DriveLetter=$dl; AccessPaths=$paths; Size=[uint64]$p.Size; IsBoot=[bool]$p.IsBoot; IsSystem=[bool]$p.IsSystem}; ` +
	`if ($v) { $r.FileSystem=[string]$v.FileSystem; $r.Label=[string]$v.FileSystemLabel; $r.FreeSpace=[uint64]$v.SizeRemaining }; ` +
	`if ($b) { $r.VolumeStatus=[string]$b.VolumeStatus; $r.EncryptionPercentage=[double]$b.EncryptionPercentage; $r.EncryptionMethod=[string]$b.EncryptionMethod; $r.ProtectionStatus=[string]$b.ProtectionStatus; ` +
	`$r.KeyProtectors=@($b.KeyProtector | Where-Object { $_ } | ForEach-Object { [ordered]@{Id=[string]$_.KeyProtectorId; Type=[string]$_.KeyProtectorType} }) }; ` +
	`[PSCustomObject]$r }); ` +
	`[PSCustomObject]@{BitLockerAvailable=$blOk; Partitions=$rows} | ConvertTo-Json -Depth 5 -Compress`

// windowsPartitionsForDisk returns every partition on diskIndex. It returns an
// empty (non-nil) slice when the disk index is unknown or the query fails.
func windowsPartitionsForDisk(diskIndex int) []shared.DiskPartition {
	if diskIndex < 0 {
		return []shared.DiskPartition{}
	}
	out, err := shared.RunPowerShell(fmt.Sprintf(windowsPartitionQuery, diskIndex))
	if err != nil {
		return []shared.DiskPartition{}
	}
	return parseWindowsPartitions(strings.TrimSpace(out))
}

// parseWindowsPartitions parses windowsPartitionQuery's JSON output. It never
// returns nil, so the payload always carries a partitions array.
func parseWindowsPartitions(output string) []shared.DiskPartition {
	parts := []shared.DiskPartition{}
	var result map[string]any
	if json.Unmarshal([]byte(output), &result) != nil || result == nil {
		return parts
	}
	blAvailable, _ := result["BitLockerAvailable"].(bool)
	for _, item := range jsonList(result["Partitions"]) {
		if m, ok := item.(map[string]any); ok {
			parts = append(parts, parseWindowsPartition(m, blAvailable))
		}
	}
	return parts
}

// parseWindowsPartition converts one partition entry of windowsPartitionQuery's
// output. blAvailable says whether Get-BitLockerVolume ran: if it did, a
// partition it didn't report (EFI, MSR, Recovery, non-NTFS) is unencrypted; if
// it didn't, nothing can be said and the state is unknown.
func parseWindowsPartition(m map[string]any, blAvailable bool) shared.DiskPartition {
	p := shared.DiskPartition{
		PartitionType: windowsPartitionType(jsonString(m, "Type")),
		VolumeLabel:   jsonString(m, "Label"),
		FileSystem:    jsonString(m, "FileSystem"),
	}
	if v, ok := m["PartitionNumber"].(float64); ok {
		if n, ok := shared.JSONInt(v); ok && n >= 0 {
			p.PartitionNumber = n
		}
	}
	if dl := strings.ToUpper(jsonString(m, "DriveLetter")); len(dl) == 1 && dl[0] >= 'A' && dl[0] <= 'Z' {
		p.DriveLetter = dl
	}
	if v, ok := m["Size"].(float64); ok {
		p.SizeBytes, _ = shared.JSONUint64(v)
	}
	if v, ok := m["FreeSpace"].(float64); ok {
		p.FreeBytes, _ = shared.JSONUint64(v)
	}
	p.IsBoot, _ = m["IsBoot"].(bool)
	p.IsSystem, _ = m["IsSystem"].(bool)
	p.VolumeGUID, p.MountPoint = windowsAccessPaths(m["AccessPaths"])

	volumeStatus, hasBitLocker := m["VolumeStatus"].(string)
	switch {
	case hasBitLocker:
		applyBitLockerVolume(&p, m, volumeStatus)
	case blAvailable:
		p.EncryptionState = encStateNone
	default:
		p.EncryptionState = encStateUnknown
	}
	return p
}

// applyBitLockerVolume fills p's encryption fields from the Get-BitLockerVolume
// entry matched to it. The state comes from VolumeStatus (is the data
// encrypted), and ProtectionStatus is reported separately, so a fully
// encrypted volume with protection suspended is still "full".
func applyBitLockerVolume(p *shared.DiskPartition, m map[string]any, volumeStatus string) {
	if v, ok := m["EncryptionPercentage"].(float64); ok && v >= 0 && v <= 100 {
		pct := v
		p.EncryptionPercentage = &pct
	}
	p.EncryptionState = bitLockerEncryptionState(volumeStatus, p.EncryptionPercentage)
	switch p.EncryptionState {
	case encStateFull, encStatePartial, encStateEncrypting, encStateDecrypting:
		p.EncryptionProvider = "BitLocker"
	}
	if em := jsonString(m, "EncryptionMethod"); em != "" && em != "None" {
		p.EncryptionMethod = em
	}
	p.ProtectionStatus = bitLockerProtectionStatus(jsonString(m, "ProtectionStatus"))
	for _, item := range jsonList(m["KeyProtectors"]) {
		kp, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kpType := jsonString(kp, "Type")
		if kpType == "" {
			continue
		}
		p.KeyProtectorTypes = append(p.KeyProtectorTypes, kpType)
		if kpType == "RecoveryPassword" && p.KeyProtectorID == "" {
			p.KeyProtectorID = jsonString(kp, "Id")
		}
	}
}

// bitLockerEncryptionState maps Get-BitLockerVolume's VolumeStatus to a
// partition encryption state. A paused conversion, or a percentage strictly
// between 0 and 100 with no recognised status, is "partial". Anything else
// unrecognised is "unknown", never "none".
func bitLockerEncryptionState(volumeStatus string, pct *float64) string {
	switch volumeStatus {
	case "FullyEncrypted":
		return encStateFull
	case "FullyDecrypted":
		return encStateNone
	case "EncryptionInProgress":
		return encStateEncrypting
	case "DecryptionInProgress":
		return encStateDecrypting
	case "EncryptionPaused", "DecryptionPaused":
		return encStatePartial
	}
	if pct != nil && *pct > 0 && *pct < 100 {
		return encStatePartial
	}
	return encStateUnknown
}

// bitLockerProtectionStatus maps ProtectionStatus ("On", "Off", "Unknown") to
// on | off | unknown.
func bitLockerProtectionStatus(s string) string {
	switch strings.ToLower(s) {
	case "on":
		return "on"
	case "off":
		return "off"
	default:
		return "unknown"
	}
}

// windowsPartitionType maps Get-Partition's Type to the names the server
// uses: "System" is the EFI system partition and "Reserved" is the Microsoft
// Reserved Partition. Other types ("Basic", "Recovery", MBR types) pass through.
func windowsPartitionType(t string) string {
	switch t {
	case "System":
		return "EFI"
	case "Reserved":
		return "MSR"
	default:
		return t
	}
}

// windowsAccessPaths picks the volume GUID path (\\?\Volume{guid}\) and any
// folder mount point out of a partition's AccessPaths. Drive-letter roots
// ("C:\") are skipped: the drive letter is reported on its own.
func windowsAccessPaths(v any) (volumeGUID, mountPoint string) {
	for _, item := range jsonList(v) {
		ap, ok := item.(string)
		if !ok {
			continue
		}
		ap = strings.TrimSpace(ap)
		switch {
		case ap == "" || isDriveRoot(ap):
		case strings.HasPrefix(strings.ToLower(ap), `\\?\volume{`):
			if volumeGUID == "" {
				volumeGUID = ap
			}
		case mountPoint == "":
			mountPoint = ap
		}
	}
	return volumeGUID, mountPoint
}

// isDriveRoot reports whether s is a drive-letter root such as "C:\" or "C:".
func isDriveRoot(s string) bool {
	s = strings.TrimSuffix(s, `\`)
	return len(s) == 2 && s[1] == ':'
}

// jsonList returns v as a list. PowerShell's ConvertTo-Json sometimes emits a
// one-element array as the bare element, so a non-list value becomes a
// one-element list and nil an empty one.
func jsonList(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	default:
		return []any{t}
	}
}

// jsonString returns m[key] trimmed when it is a string, else "".
func jsonString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// windowsDiskEncryption derives the disk-level encryption status and type
// from the disk's partitions (see summarizeDiskEncryption). It no longer looks
// at ProtectionStatus, so an encrypted volume with BitLocker suspended still
// counts as enabled.
func windowsDiskEncryption(parts []shared.DiskPartition) (status, encType string) {
	status, decider := summarizeDiskEncryption(parts)
	switch status {
	case "enabled":
		return status, classifyBitLockerMethod(decider.EncryptionMethod, "unknown")
	case "disabled":
		return status, "none"
	default:
		return "unknown", "unknown"
	}
}

// classifyBitLockerMethod maps BitLocker's EncryptionMethod enum string to a canonical
// encryption type, given encryption is already known to be enabled. current is
// returned unchanged when no active method is reported.
func classifyBitLockerMethod(em, current string) string {
	switch em {
	case "HardwareEncryption":
		return "hardware"
	case "", "None", "Unspecified":
		return current // encryption on but no active method reported
	default: // AES128, AES256, XtsAes128, XtsAes256
		return "software"
	}
}

// buildWindowsDiskDevice assembles a shared.DiskDevice from one Get-PhysicalDisk entry
// and its partitions. The disk-level drive letter, filesystem and free space come
// from the first lettered partition, as they did before partitions were reported.
func buildWindowsDiskDevice(info physicalDiskInfo, parts []shared.DiskPartition) shared.DiskDevice {
	encStatus, encType := windowsDiskEncryption(parts)
	d := shared.DiskDevice{
		Description:      info.description,
		Type:             "Physical disk drive",
		Capacity:         info.totalBytes,
		EncryptionStatus: encStatus,
		EncryptionType:   encType,
		SerialNumber:     info.serial,
		Manufacturer:     manufacturerFromModel(info.description),
		DriveType:        windowsDriveType(info.mediaType, info.busType),
		HealthStatus:     windowsHealthStatus(info.healthStr),
		InterfaceType:    windowsInterfaceType(info.busType),
		DiskNumber:       info.diskIndex,
		Partitions:       parts,
	}
	for _, p := range parts {
		if p.DriveLetter != "" {
			d.DriveLetter = p.DriveLetter
			d.FileSystem = p.FileSystem
			d.FreeCapacity = p.FreeBytes
			break
		}
	}
	return d
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
