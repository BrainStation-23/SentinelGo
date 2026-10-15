package disk

import (
	"context"
	"encoding/json"
	"math"
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

	layouts := linuxDiskLayouts()
	diskNumber := 0
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

		layout, ok := layouts[name]
		if !ok {
			layout.partitions = []shared.DiskPartition{}
		}
		encryptionStatus, encryptionType := linuxEncryptionStatus(devPath, layout)
		var freeBytes uint64
		if layout.mountPoint != "" {
			freeBytes = linuxFreeBytesForMount(layout.mountPoint)
		}

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
			FileSystem:       layout.fileSystem,
			MountPoint:       layout.mountPoint,
			DiskNumber:       diskNumber,
			Partitions:       layout.partitions,
		})
		diskNumber++
	}
	return disks
}

// lsblk column sets for the partition tree. PARTTYPENAME needs util-linux
// 2.33 and PARTN 2.39, and lsblk rejects an unknown column outright, so older
// systems are retried with the basic set (the partition number then comes
// from the device name).
const (
	lsblkTreeColumns      = "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID,PARTTYPENAME,PARTN"
	lsblkTreeColumnsBasic = "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID"
)

// lsblkNode is one device in `lsblk -J` output. SIZE and PARTN are numbers or
// strings depending on the util-linux version; null strings decode as "".
type lsblkNode struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Size         any         `json:"size"`
	FSType       string      `json:"fstype"`
	MountPoint   string      `json:"mountpoint"`
	Label        string      `json:"label"`
	UUID         string      `json:"uuid"`
	PartTypeName string      `json:"parttypename"`
	PartN        any         `json:"partn"`
	Children     []lsblkNode `json:"children"`
}

// linuxDiskLayout is what the partition tree says about one disk.
type linuxDiskLayout struct {
	partitions []shared.DiskPartition
	// fileSystem and mountPoint are the disk's primary mount: "/" if it is
	// anywhere on the disk, else the first mounted device (swap excluded).
	fileSystem string
	mountPoint string
	// luks is true when the disk or anything on it is a LUKS container, which
	// also covers LUKS on the whole disk, where there are no partitions.
	luks bool
	// wholeDiskFS is the file system written straight onto the disk, with no
	// partition table (common on VMs and WSL).
	wholeDiskFS string
}

// linuxDiskLayouts runs lsblk once for every disk and returns each disk's
// layout keyed by device name ("sda", "nvme0n1"). Free space is filled in from
// df for every mounted partition.
func linuxDiskLayouts() map[string]linuxDiskLayout {
	out, err := shared.RunCommand("lsblk", "-J", "-b", "-o", lsblkTreeColumns)
	if err != nil {
		if out, err = shared.RunCommand("lsblk", "-J", "-b", "-o", lsblkTreeColumnsBasic); err != nil {
			return nil
		}
	}
	layouts := parseLinuxDiskLayouts(out)
	for _, l := range layouts {
		for i := range l.partitions {
			if mp := l.partitions[i].MountPoint; mp != "" {
				l.partitions[i].FreeBytes = linuxFreeBytesForMount(mp)
			}
		}
	}
	return layouts
}

// parseLinuxDiskLayouts parses `lsblk -J -b -o <lsblkTreeColumns>` output into
// per-disk layouts. Devices that aren't disks (loop, rom) are skipped.
func parseLinuxDiskLayouts(out string) map[string]linuxDiskLayout {
	var raw struct {
		Blockdevices []lsblkNode `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &raw) != nil {
		return nil
	}
	layouts := map[string]linuxDiskLayout{}
	for _, disk := range raw.Blockdevices {
		if disk.Type != "disk" || disk.Name == "" {
			continue
		}
		l := linuxDiskLayout{partitions: []shared.DiskPartition{}, luks: hasLUKS(disk), wholeDiskFS: strings.TrimSpace(disk.FSType)}
		for _, child := range disk.Children {
			if child.Type == "part" {
				l.partitions = append(l.partitions, linuxPartition(child))
			}
		}
		l.fileSystem, l.mountPoint = primaryMount(disk)
		layouts[disk.Name] = l
	}
	return layouts
}

// linuxPartition converts one lsblk "part" node. A LUKS partition is "full"
// whether or not it is open; when it is open, the file system and mount point
// come from the mapper device on top of it, which is what the admin sees. A
// partition with no file system lsblk can identify is "unknown".
func linuxPartition(n lsblkNode) shared.DiskPartition {
	p := shared.DiskPartition{
		PartitionNumber: linuxPartitionNumber(n),
		PartitionType:   strings.TrimSpace(n.PartTypeName),
		VolumeLabel:     strings.TrimSpace(n.Label),
		VolumeGUID:      strings.TrimSpace(n.UUID),
		FileSystem:      strings.TrimSpace(n.FSType),
		SizeBytes:       lsblkUint(n.Size),
	}
	fs, mp := primaryMount(n)
	p.MountPoint = mp
	if p.FileSystem == "" || p.FileSystem == "crypto_LUKS" {
		if fs == "" {
			fs = firstFileSystem(n.Children)
		}
		if fs != "" {
			p.FileSystem = fs
		}
	}
	p.IsBoot = hasMount(n, "/")
	pt := strings.ToLower(p.PartitionType)
	p.IsSystem = pt == "efi system" || mp == "/boot/efi" || mp == "/efi"

	switch {
	case hasLUKS(n):
		p.EncryptionState = encStateFull
		p.EncryptionProvider = "LUKS"
	case p.FileSystem == "":
		p.EncryptionState = encStateUnknown
	default:
		p.EncryptionState = encStateNone
	}
	return p
}

// linuxPartitionNumber returns PARTN when lsblk reported it, else the trailing
// digits of the device name (sda3 -> 3, nvme0n1p3 -> 3).
func linuxPartitionNumber(n lsblkNode) int {
	if v := lsblkUint(n.PartN); v > 0 && v <= math.MaxInt32 {
		return int(v)
	}
	i := len(n.Name)
	for i > 0 && n.Name[i-1] >= '0' && n.Name[i-1] <= '9' {
		i--
	}
	v, err := strconv.ParseUint(n.Name[i:], 10, 31)
	if err != nil {
		return 0
	}
	return int(v)
}

// lsblkUint reads a SIZE/PARTN value, which lsblk emits as a number or a
// numeric string depending on its version.
func lsblkUint(v any) uint64 {
	switch t := v.(type) {
	case float64:
		n, _ := shared.JSONUint64(t)
		return n
	case string:
		n, _ := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		return n
	}
	return 0
}

// usableMount returns n's mount point, or "" for swap ("[SWAP]") and unmounted.
func usableMount(n lsblkNode) string {
	mp := strings.TrimSpace(n.MountPoint)
	if strings.HasPrefix(mp, "[") {
		return ""
	}
	return mp
}

// primaryMount walks n and its descendants in lsblk order and returns the
// file system and mount point of the device mounted at "/", or failing that
// the first mounted one.
func primaryMount(n lsblkNode) (fileSystem, mountPoint string) {
	if mp := usableMount(n); mp != "" {
		fileSystem, mountPoint = strings.TrimSpace(n.FSType), mp
		if mp == "/" {
			return fileSystem, mountPoint
		}
	}
	for _, c := range n.Children {
		fs, mp := primaryMount(c)
		if mp == "/" {
			return fs, mp
		}
		if mountPoint == "" && mp != "" {
			fileSystem, mountPoint = fs, mp
		}
	}
	return fileSystem, mountPoint
}

// firstFileSystem returns the first file system found among nodes and their
// descendants, e.g. the file system inside an open but unmounted LUKS mapper.
func firstFileSystem(nodes []lsblkNode) string {
	for _, c := range nodes {
		if fs := strings.TrimSpace(c.FSType); fs != "" && fs != "crypto_LUKS" {
			return fs
		}
		if fs := firstFileSystem(c.Children); fs != "" {
			return fs
		}
	}
	return ""
}

// hasLUKS reports whether n or any descendant is a LUKS container or an open
// dm-crypt mapping (LUKS on a partition, on LVM, or on the whole disk).
func hasLUKS(n lsblkNode) bool {
	if n.FSType == "crypto_LUKS" || n.Type == "crypt" {
		return true
	}
	for _, c := range n.Children {
		if hasLUKS(c) {
			return true
		}
	}
	return false
}

// hasMount reports whether n or any descendant is mounted at mountPoint.
func hasMount(n lsblkNode, mountPoint string) bool {
	if usableMount(n) == mountPoint {
		return true
	}
	for _, c := range n.Children {
		if hasMount(c, mountPoint) {
			return true
		}
	}
	return false
}

// linuxEncryptionStatus derives the disk-level encryption status from the
// disk's layout. The partitions decide when they can, so an unencrypted root
// stays disabled even if another partition is a LUKS vault. When they can't
// (LUKS or a file system on the whole disk, with no partitions), LUKS counts
// as software encryption and a plain file system as unencrypted. A
// self-encrypting drive with locking on counts as hardware encryption.
func linuxEncryptionStatus(devPath string, layout linuxDiskLayout) (status, encType string) {
	status, _ = summarizeDiskEncryption(layout.partitions)
	if status == "enabled" || (status == "unknown" && layout.luks) {
		return "enabled", "software"
	}
	if linuxSEDLocking(devPath) {
		return "enabled", "hardware"
	}
	if status == "disabled" || (len(layout.partitions) == 0 && layout.wholeDiskFS != "") {
		return "disabled", "none"
	}
	return "unknown", "unknown"
}

// linuxSEDLocking reports whether sedutil-cli says devPath is a
// self-encrypting drive with locking enabled.
func linuxSEDLocking(devPath string) bool {
	out, err := shared.RunCommand("sedutil-cli", "--query", devPath)
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "locking enabled") || strings.Contains(lower, "locked")
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
	smartctl, ok := binpath.Lookup("smartctl")
	if !ok {
		return "Unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 — devPath is constructed from lsblk output, always "/dev/<name>"
	out, _ := exec.CommandContext(ctx, smartctl, "-H", devPath).Output()
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
