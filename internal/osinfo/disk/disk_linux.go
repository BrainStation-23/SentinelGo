package disk

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
	"sentinelgo/internal/osinfo/shared"
)

func getDisks() []shared.DiskDevice {
	var disks []shared.DiskDevice

	// --json gives structured output; -d shows only devices (no partitions); -b outputs raw bytes.
	out, err := shared.RunCommand("lsblk", "--json", "-d", "-b", "-o", "NAME,TYPE,MODEL,SERIAL,SIZE,ROTA,TRAN")
	if err != nil {
		return disks
	}

	var raw struct {
		Blockdevices []map[string]any `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &raw) != nil {
		return disks
	}

	for _, dev := range raw.Blockdevices {
		if t, _ := dev["type"].(string); t != "disk" {
			continue
		}

		name, _ := dev["name"].(string)
		var model, serial string
		if v, ok := dev["model"].(string); ok {
			model = strings.TrimSpace(v)
		}
		if v, ok := dev["serial"].(string); ok {
			serial = strings.TrimSpace(v)
		}

		// SIZE is bytes as string or number depending on lsblk version.
		var sizeBytes uint64
		switch v := dev["size"].(type) {
		case float64:
			sizeBytes = uint64(v)
		case string:
			sizeBytes, _ = strconv.ParseUint(v, 10, 64)
		}

		// ROTA is bool or string ("0"/"1") depending on kernel/util-linux version.
		var rota bool
		switch v := dev["rota"].(type) {
		case bool:
			rota = v
		case string:
			rota = v == "1"
		case float64:
			rota = v != 0
		}

		tran, _ := dev["tran"].(string)
		devPath := "/dev/" + name

		encryptionStatus, encryptionType := linuxEncryptionStatus(devPath)
		fileSystem, mountPoint, freeBytes := linuxPartitionInfo(devPath)

		disks = append(disks, shared.DiskDevice{
			FreeCapacity:     freeBytes,
			Description:      model,
			Type:             "Physical disk drive",
			Capacity:         sizeBytes,
			EncryptionStatus: encryptionStatus,
			EncryptionType:   encryptionType,
			SerialNumber:     serial,
			Manufacturer:     manufacturerFromModel(model),
			DriveType:        linuxDriveType(name, rota),
			HealthStatus:     linuxHealthStatus(devPath),
			InterfaceType:    linuxInterfaceType(tran),
			FileSystem:       fileSystem,
			MountPoint:       mountPoint,
		})
	}
	return disks
}

func linuxEncryptionStatus(devPath string) (status, encType string) {
	status, encType = "unknown", "unknown"
	if out, err := shared.RunCommand("lsblk", "-o", "FSTYPE", "-n", devPath); err == nil {
		status = "disabled"
		encType = "none"
		if strings.Contains(out, "crypto_LUKS") {
			status = "enabled"
			encType = "software"
		}
	}
	if status != "enabled" {
		if out, err := shared.RunCommand("dmsetup", "status", "--target", "crypt"); err == nil {
			if strings.TrimSpace(out) != "" {
				status = "enabled"
				encType = "software"
			}
		}
	}
	if encType != "software" {
		if out, err := shared.RunCommand("sedutil-cli", "--query", devPath); err == nil {
			lower := strings.ToLower(out)
			if strings.Contains(lower, "locking enabled") || strings.Contains(lower, "locked") {
				status = "enabled"
				encType = "hardware"
			}
		}
	}
	return
}

// linuxPartitionInfo returns the filesystem type, primary mount point, and free bytes for
// the first mounted partition on devPath. Prefers "/" over other mount points.
func linuxPartitionInfo(devPath string) (fileSystem, mountPoint string, freeBytes uint64) {
	// -n suppresses header, -l gives flat list including child partitions and dm-crypt mappers.
	out, err := shared.RunCommand("lsblk", "-o", "FSTYPE,MOUNTPOINT", "-nl", devPath)
	if err != nil {
		return
	}

	fileSystem, mountPoint = selectPrimaryPartition(out)
	if mountPoint == "" {
		return
	}
	freeBytes = linuxFreeBytesForMount(mountPoint)
	return
}

// selectPrimaryPartition scans lsblk's flat "FSTYPE MOUNTPOINT" listing and picks the
// primary mounted partition: the first one found, overridden by "/" if present.
// Unmounted partitions and swap are skipped.
func selectPrimaryPartition(lsblkOut string) (fileSystem, mountPoint string) {
	for _, line := range strings.Split(lsblkOut, "\n") {
		fs, mp := parsePartitionLine(line)
		if mp == "" || mp == "[SWAP]" {
			continue
		}
		// Take first found; override if we find "/"
		if mountPoint == "" || mp == "/" {
			fileSystem = fs
			mountPoint = mp
		}
		if mp == "/" {
			break
		}
	}
	return fileSystem, mountPoint
}

// parsePartitionLine parses one "FSTYPE MOUNTPOINT" line from `lsblk -nl`. FSTYPE may be
// empty, in which case only MOUNTPOINT is present (e.g. "   /boot/efi" → ["/boot/efi"]).
func parsePartitionLine(line string) (fileSystem, mountPoint string) {
	fields := strings.Fields(line)
	switch len(fields) {
	case 2:
		return fields[0], fields[1]
	case 1:
		if strings.HasPrefix(fields[0], "/") {
			return "", fields[0]
		}
	}
	return "", ""
}

// linuxFreeBytesForMount runs `df -B1` against mountPoint and parses the free-bytes
// column (4th field of the data row). Returns 0 if the command fails or the output
// doesn't have the expected shape.
func linuxFreeBytesForMount(mountPoint string) uint64 {
	dfOut, err := shared.RunCommand("df", "-B1", mountPoint)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(dfOut), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0
	}
	freeBytes, _ := strconv.ParseUint(fields[3], 10, 64)
	return freeBytes
}

// linuxDriveType classifies a disk as NVMe, SSD, or HDD.
// NVMe device names take priority; ROTA=true means spinning disk (HDD).
func linuxDriveType(name string, rota bool) string {
	if strings.HasPrefix(name, "nvme") {
		return "NVMe"
	}
	if rota {
		return "HDD"
	}
	return "SSD"
}

func linuxInterfaceType(tran string) string {
	switch strings.ToLower(tran) {
	case "nvme":
		return "NVMe"
	case "sata":
		return "SATA"
	case "usb":
		return "USB"
	case "sas":
		return "SAS"
	case "ata":
		return "ATA"
	case "mmc":
		return "MMC"
	case "":
		return "Unknown"
	default:
		return strings.ToUpper(tran)
	}
}

// linuxHealthStatus runs smartctl -H and parses the overall-health assessment.
// smartctl uses exit-code bit-flags (e.g. bit 2 = disk failing), so RunCommand would
// return an error and discard stdout. We call exec directly to capture stdout regardless
// of exit code.
func linuxHealthStatus(devPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 — devPath is constructed from lsblk output, always "/dev/<name>"
	out, _ := exec.CommandContext(ctx, binpath.Resolve("smartctl"), "-H", devPath).Output()
	if len(out) == 0 {
		return "Unknown"
	}
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "passed") || strings.Contains(lower, ": ok") {
		return "Healthy"
	}
	if strings.Contains(lower, "failed") {
		return "Unhealthy"
	}
	return "Unknown"
}
