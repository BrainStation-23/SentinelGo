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

	// FileVault and T2/Apple Silicon are system-wide properties — run once outside the loop.
	encryptionStatus := "unknown"
	encryptionType := "unknown"
	if out, err := shared.RunCommand("fdesetup", "status"); err == nil {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "filevault is on") {
			encryptionStatus = "enabled"
		} else if strings.Contains(lower, "filevault is off") {
			encryptionStatus = "disabled"
			encryptionType = "none"
		}
	}
	if encryptionStatus == "enabled" {
		if out, err := shared.RunCommand("system_profiler", "SPiBridgeDataType", "-json"); err == nil {
			if strings.Contains(out, "ibridge_model_name") {
				encryptionType = "hardware"
			} else {
				encryptionType = "software"
			}
		}
	}

	for _, s := range storageArr {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}

		var description, serial, fileSystem, mountPoint string
		var totalBytes, freeBytes uint64

		if v, ok := sm["_name"].(string); ok {
			description = v
		}
		if v, ok := sm["size_in_bytes"].(float64); ok {
			totalBytes = uint64(v)
		}
		if v, ok := sm["free_space_in_bytes"].(float64); ok {
			freeBytes = uint64(v)
		}
		if v, ok := sm["file_system"].(string); ok {
			fileSystem = strings.TrimSpace(v)
		}
		if v, ok := sm["mount_point"].(string); ok {
			mountPoint = strings.TrimSpace(v)
		}

		driveType := "Unknown"
		interfaceType := "Unknown"
		healthStatus := "Unknown"

		if pd, ok := sm["physical_drive"].(map[string]any); ok {
			if v, ok := pd["device_name"].(string); ok && v != "" {
				serial = v
			}
			mediumType, _ := pd["medium_type"].(string)
			protocol, _ := pd["protocol"].(string)
			driveType = macDriveType(mediumType, protocol)
			interfaceType = macInterfaceType(protocol)
			if v, ok := pd["smart_status"].(string); ok {
				healthStatus = macHealthStatus(v)
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
			DriveType:        driveType,
			HealthStatus:     healthStatus,
			InterfaceType:    interfaceType,
			FileSystem:       fileSystem,
			MountPoint:       mountPoint,
		})
	}
	return deduplicateBySerial(disks)
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
