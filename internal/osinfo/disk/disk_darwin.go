package disk

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getDisks() []shared.DiskDevice {
	var disks []shared.DiskDevice

	output, err := shared.RunCommand("system_profiler", "SPStorageDataType", "-json")
	if err != nil {
		return disks
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return disks
	}
	storageRaw, ok := result["SPStorageDataType"]
	if !ok {
		return disks
	}
	storageArr, ok := storageRaw.([]any)
	if !ok {
		return disks
	}

	// FileVault and T2/Apple Silicon are system-wide properties — computed once outside the loop.
	encStatus, encType := macSystemEncryption()

	for _, s := range storageArr {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		entry := parseMacStorageEntry(sm)
		pd := parseMacPhysicalDrive(sm)
		disks = append(disks, buildMacDiskDevice(entry, pd, encStatus, encType))
	}
	return deduplicateBySerial(disks)
}

// macSystemEncryption reports FileVault status and, when enabled, whether the
// encryption is hardware- or software-backed. FileVault and T2/Apple Silicon are
// system-wide properties, so this is queried once rather than per storage entry.
func macSystemEncryption() (status, encType string) {
	status, encType = "unknown", "unknown"
	out, err := shared.RunCommand("fdesetup", "status")
	if err != nil {
		return status, encType
	}

	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "filevault is on"):
		status = "enabled"
	case strings.Contains(lower, "filevault is off"):
		status = "disabled"
		encType = "none"
	}
	if status != "enabled" {
		return status, encType
	}

	if ibridgeOut, err := shared.RunCommand("system_profiler", "SPiBridgeDataType", "-json"); err == nil {
		if strings.Contains(ibridgeOut, "ibridge_model_name") {
			encType = "hardware"
		} else {
			encType = "software"
		}
	}
	return status, encType
}

// macStorageEntry bundles the basic fields parsed from one SPStorageDataType entry.
type macStorageEntry struct {
	description string
	fileSystem  string
	mountPoint  string
	totalBytes  uint64
	freeBytes   uint64
}

// parseMacStorageEntry extracts the volume-level fields of one SPStorageDataType entry.
func parseMacStorageEntry(sm map[string]any) macStorageEntry {
	var entry macStorageEntry
	if v, ok := sm["_name"].(string); ok {
		entry.description = v
	}
	if v, ok := sm["size_in_bytes"].(float64); ok {
		entry.totalBytes = uint64(v)
	}
	if v, ok := sm["free_space_in_bytes"].(float64); ok {
		entry.freeBytes = uint64(v)
	}
	if v, ok := sm["file_system"].(string); ok {
		entry.fileSystem = strings.TrimSpace(v)
	}
	if v, ok := sm["mount_point"].(string); ok {
		entry.mountPoint = strings.TrimSpace(v)
	}
	return entry
}

// macPhysicalDriveInfo bundles the fields derived from an SPStorageDataType entry's
// nested physical_drive object.
type macPhysicalDriveInfo struct {
	serial        string
	driveType     string
	interfaceType string
	healthStatus  string
}

// parseMacPhysicalDrive extracts serial number, drive type, interface, and health from
// an SPStorageDataType entry's physical_drive object. Absent that object, it returns
// the "Unknown" defaults and an empty serial.
func parseMacPhysicalDrive(sm map[string]any) macPhysicalDriveInfo {
	info := macPhysicalDriveInfo{driveType: "Unknown", interfaceType: "Unknown", healthStatus: "Unknown"}
	pd, ok := sm["physical_drive"].(map[string]any)
	if !ok {
		return info
	}

	if v, ok := pd["device_name"].(string); ok && v != "" {
		info.serial = v
	}
	mediumType, _ := pd["medium_type"].(string)
	protocol, _ := pd["protocol"].(string)
	info.driveType = macDriveType(mediumType, protocol)
	info.interfaceType = macInterfaceType(protocol)
	if v, ok := pd["smart_status"].(string); ok {
		info.healthStatus = macHealthStatus(v)
	}
	return info
}

// buildMacDiskDevice assembles a shared.DiskDevice from one SPStorageDataType entry's
// parsed volume and physical-drive details plus the system-wide encryption status.
func buildMacDiskDevice(entry macStorageEntry, pd macPhysicalDriveInfo, encStatus, encType string) shared.DiskDevice {
	return shared.DiskDevice{
		FreeCapacity:     entry.freeBytes,
		Description:      entry.description,
		Type:             "Physical disk drive",
		Capacity:         entry.totalBytes,
		EncryptionStatus: encStatus,
		EncryptionType:   encType,
		SerialNumber:     pd.serial,
		Manufacturer:     manufacturerFromModel(entry.description),
		DriveType:        pd.driveType,
		HealthStatus:     pd.healthStatus,
		InterfaceType:    pd.interfaceType,
		FileSystem:       entry.fileSystem,
		MountPoint:       entry.mountPoint,
	}
}

// deduplicateBySerial collapses APFS volume entries that share the same physical
// drive serial number into a single representative entry. system_profiler returns
// one entry per APFS volume, not per physical disk, so a single NVMe SSD can
// appear 3+ times. Entries with an empty serial are kept as-is (no safe key).
// The root-mounted volume ("/") is preferred as the representative when present.
func deduplicateBySerial(disks []shared.DiskDevice) []shared.DiskDevice {
	seen := map[string]int{} // serial -> index in result
	result := make([]shared.DiskDevice, 0, len(disks))
	for _, d := range disks {
		if d.SerialNumber == "" {
			result = append(result, d)
			continue
		}
		idx, exists := seen[d.SerialNumber]
		if !exists {
			seen[d.SerialNumber] = len(result)
			result = append(result, d)
		} else if d.MountPoint == "/" {
			result[idx] = d // root volume is the canonical representative
		}
	}
	return result
}

// macDriveType derives SSD/HDD/NVMe from system_profiler's medium_type and protocol fields.
// Apple Fabric and PCIe are NVMe internally even when medium_type says "SSD".
func macDriveType(mediumType, protocol string) string {
	lower := strings.ToLower(mediumType)
	protoLower := strings.ToLower(protocol)
	if strings.Contains(lower, "ssd") || strings.Contains(lower, "solid") {
		if protoLower == "apple fabric" || strings.Contains(protoLower, "pci") || strings.Contains(protoLower, "nvme") {
			return "NVMe"
		}
		return "SSD"
	}
	if strings.Contains(lower, "hard disk") || strings.Contains(lower, "hdd") || strings.Contains(lower, "rotational") {
		return "HDD"
	}
	return "Unknown"
}

// macInterfaceType maps system_profiler's protocol string to a canonical interface name.
// Apple Fabric is the NVMe-based interconnect on Apple Silicon.
func macInterfaceType(protocol string) string {
	lower := strings.ToLower(protocol)
	switch {
	case lower == "apple fabric":
		return "NVMe"
	case strings.Contains(lower, "nvme"):
		return "NVMe"
	case strings.Contains(lower, "pci"):
		return "NVMe"
	case lower == "sata":
		return "SATA"
	case strings.Contains(lower, "usb"):
		return "USB"
	case strings.Contains(lower, "thunderbolt"):
		return "Thunderbolt"
	case lower == "":
		return "Unknown"
	default:
		return protocol
	}
}

// macHealthStatus maps system_profiler's smart_status field to canonical values.
// "Verified" is Apple's term for a passing SMART self-assessment.
func macHealthStatus(smartStatus string) string {
	switch strings.ToLower(strings.TrimSpace(smartStatus)) {
	case "verified":
		return "Healthy"
	case "failing":
		return "Unhealthy"
	default:
		return "Unknown"
	}
}
