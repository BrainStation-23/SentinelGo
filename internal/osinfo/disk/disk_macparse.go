package disk

// macOS partition parsers. No OS suffix so they are tested everywhere;
// disk_darwin.go calls them.

import (
	"regexp"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// macWholeDiskRe extracts the whole disk ("disk3") and its number from a BSD
// name such as "disk3", "disk3s1" or "disk3s1s1".
var macWholeDiskRe = regexp.MustCompile(`^disk(\d+)`)

// macSliceRe extracts the slice number from a BSD name ("disk0s2" -> 2).
var macSliceRe = regexp.MustCompile(`^disk\d+s(\d+)`)

// macPercentRe extracts fdesetup's conversion progress
// ("Percent completed = 42.0").
var macPercentRe = regexp.MustCompile(`(?i)percent completed\s*=\s*([0-9.]+)`)

// macLayout is the partition data for every physical disk, from
// `diskutil list -plist` and `diskutil apfs list -plist`.
type macLayout struct {
	// partitions maps a physical whole disk ("disk0") to its partitions. An
	// APFS container's partition is replaced by the container's volumes,
	// which is where the mount points and FileVault state live.
	partitions map[string][]shared.DiskPartition
	// physicalDisk maps an APFS container disk ("disk3") to the physical
	// disk holding it ("disk0").
	physicalDisk map[string]string
}

// macAPFSContainer is one container from `diskutil apfs list -plist`.
type macAPFSContainer struct {
	ref     string   // container disk, "disk3"
	stores  []string // physical store partitions, "disk0s2"
	ceiling uint64
	free    uint64
	volumes []map[string]any
}

// parseMacLayout builds the layout from decoded `diskutil list -plist` and
// `diskutil apfs list -plist` output. fdesetup is `fdesetup status` output,
// used to tell encryption from decryption while a conversion runs.
func parseMacLayout(list, apfs any, fdesetup string) macLayout {
	l := macLayout{partitions: map[string][]shared.DiskPartition{}, physicalDisk: map[string]string{}}
	byStore := map[string]macAPFSContainer{}
	for _, c := range parseMacAPFSContainers(apfs) {
		for _, store := range c.stores {
			byStore[store] = c
		}
		if len(c.stores) > 0 {
			l.physicalDisk[c.ref] = macWholeDisk(c.stores[0])
		}
	}

	root, _ := list.(map[string]any)
	disks, _ := root["AllDisksAndPartitions"].([]any)
	mounts := macVolumeMounts(disks)
	for _, disk := range plistMaps(disks) {
		id := plistString(disk, "DeviceIdentifier")
		// Synthesized APFS container disks are listed too; their volumes are
		// reported under the physical disk instead.
		if _, synthesized := disk["APFSPhysicalStores"]; synthesized || macWholeDisk(id) != id {
			continue
		}
		l.partitions[id] = macDiskPartitions(disk, byStore, mounts, fdesetup)
	}
	return l
}

// macDiskPartitions lists one physical disk's partitions, expanding each APFS
// physical store into its container's volumes.
func macDiskPartitions(disk map[string]any, byStore map[string]macAPFSContainer, mounts map[string]string, fdesetup string) []shared.DiskPartition {
	parts := []shared.DiskPartition{}
	for _, sm := range plistMaps(disk["Partitions"]) {
		c, isStore := byStore[plistString(sm, "DeviceIdentifier")]
		if !isStore {
			parts = append(parts, macSlicePartition(sm))
			continue
		}
		for _, v := range c.volumes {
			parts = append(parts, macAPFSVolume(v, c, mounts, fdesetup))
		}
	}
	return parts
}

// parseMacAPFSContainers reads the containers of `diskutil apfs list -plist`.
func parseMacAPFSContainers(apfs any) []macAPFSContainer {
	root, _ := apfs.(map[string]any)
	var out []macAPFSContainer
	for _, m := range plistMaps(root["Containers"]) {
		c := macAPFSContainer{
			ref:     plistString(m, "ContainerReference"),
			ceiling: plistUint(m["CapacityCeiling"]),
			free:    plistUint(m["CapacityFree"]),
		}
		c.volumes = plistMaps(m["Volumes"])
		for _, sm := range plistMaps(m["PhysicalStores"]) {
			if id := plistString(sm, "DeviceIdentifier"); id != "" {
				c.stores = append(c.stores, id)
			}
		}
		out = append(out, c)
	}
	return out
}

// macVolumeMounts maps each APFS volume ("disk3s1") to its mount point, from
// the APFSVolumes of `diskutil list -plist`. Since Big Sur the system volume
// itself is not mounted: a sealed snapshot of it is mounted at "/", so
// snapshot mount points count too.
func macVolumeMounts(disks []any) map[string]string {
	mounts := map[string]string{}
	for _, item := range disks {
		disk, _ := item.(map[string]any)
		for _, vm := range plistMaps(disk["APFSVolumes"]) {
			if mp := macVolumeMount(vm); mp != "" {
				mounts[plistString(vm, "DeviceIdentifier")] = mp
			}
		}
	}
	return mounts
}

// macVolumeMount returns an APFS volume's mount point, or that of its first
// mounted snapshot.
func macVolumeMount(vm map[string]any) string {
	if mp := plistString(vm, "MountPoint"); mp != "" {
		return mp
	}
	for _, sm := range plistMaps(vm["MountedSnapshots"]) {
		if mp := plistString(sm, "SnapshotMountPoint"); mp != "" {
			return mp
		}
	}
	return ""
}

// macAPFSVolume converts one APFS volume. Volumes share their container's
// space, so the size and free space are the container's (as Finder shows
// them).
func macAPFSVolume(v map[string]any, c macAPFSContainer, mounts map[string]string, fdesetup string) shared.DiskPartition {
	id := plistString(v, "DeviceIdentifier")
	p := shared.DiskPartition{
		PartitionNumber: macSliceNumber(id),
		PartitionType:   "APFS Volume",
		MountPoint:      mounts[id],
		VolumeLabel:     plistString(v, "Name"),
		VolumeGUID:      plistString(v, "APFSVolumeUUID"),
		FileSystem:      "APFS",
		SizeBytes:       c.ceiling,
		FreeBytes:       c.free,
	}
	if roles, _ := v["Roles"].([]any); len(roles) > 0 {
		if role, _ := roles[0].(string); role != "" {
			p.PartitionType = "APFS " + role
		}
	}
	p.IsBoot = p.MountPoint == "/"
	p.EncryptionState = macVolumeEncryptionState(v, fdesetup)
	switch p.EncryptionState {
	case encStateFull, encStateEncrypting, encStateDecrypting:
		p.EncryptionProvider = "FileVault"
	}
	if p.EncryptionState == encStateEncrypting || p.EncryptionState == encStateDecrypting {
		p.EncryptionPercentage = macConversionPercent(fdesetup)
	}
	return p
}

// macVolumeEncryptionState maps an APFS volume's FileVault flags to a
// partition encryption state. A running conversion (CryptoMigrationOn) is
// "decrypting" when fdesetup says so and "encrypting" otherwise. A locked
// volume is necessarily encrypted. With no FileVault or Encryption flag at
// all the state is "unknown".
func macVolumeEncryptionState(v map[string]any, fdesetup string) string {
	if on, ok := shared.PlistBool(v["CryptoMigrationOn"]); ok && on {
		if strings.Contains(strings.ToLower(fdesetup), "decryption in progress") {
			return encStateDecrypting
		}
		return encStateEncrypting
	}
	if locked, ok := shared.PlistBool(v["Locked"]); ok && locked {
		return encStateFull
	}
	fv, ok := shared.PlistBool(v["FileVault"])
	if !ok {
		fv, ok = shared.PlistBool(v["Encryption"])
	}
	switch {
	case !ok:
		return encStateUnknown
	case fv:
		return encStateFull
	default:
		return encStateNone
	}
}

// macConversionPercent returns fdesetup's "Percent completed" value, or nil
// when it isn't shown or isn't a valid percentage.
func macConversionPercent(fdesetup string) *float64 {
	m := macPercentRe.FindStringSubmatch(fdesetup)
	if m == nil {
		return nil
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil || pct < 0 || pct > 100 {
		return nil
	}
	return &pct
}

// macSlicePartition converts a partition that isn't an APFS physical store:
// the EFI partition on Intel Macs, HFS+, or another OS's partitions. Only the
// EFI partition is known to be unencrypted; anything else (it could be
// BitLocker or CoreStorage) is "unknown".
func macSlicePartition(sm map[string]any) shared.DiskPartition {
	content := plistString(sm, "Content")
	p := shared.DiskPartition{
		PartitionNumber: macSliceNumber(plistString(sm, "DeviceIdentifier")),
		PartitionType:   content,
		MountPoint:      plistString(sm, "MountPoint"),
		VolumeLabel:     plistString(sm, "VolumeName"),
		VolumeGUID:      plistString(sm, "VolumeUUID"),
		SizeBytes:       plistUint(sm["Size"]),
		EncryptionState: encStateUnknown,
	}
	if p.VolumeGUID == "" {
		p.VolumeGUID = plistString(sm, "DiskUUID")
	}
	switch content {
	case "EFI":
		p.IsSystem = true
		p.EncryptionState = encStateNone
	case "Apple_APFS_Recovery":
		p.PartitionType = "Recovery"
	}
	p.IsBoot = p.MountPoint == "/"
	return p
}

// macPhysicalDiskFor returns the physical whole disk ("disk0") holding a
// volume's BSD name ("disk3s1s1"), following an APFS container back to its
// physical store. It returns "" when bsdName isn't a disk.
func macPhysicalDiskFor(bsdName string, layout macLayout) string {
	whole := macWholeDisk(bsdName)
	if physical, ok := layout.physicalDisk[whole]; ok && physical != "" {
		return physical
	}
	return whole
}

// macWholeDisk returns the whole disk of a BSD name ("disk3s1s1" -> "disk3"),
// or "" when name isn't a disk.
func macWholeDisk(name string) string {
	return macWholeDiskRe.FindString(name)
}

// macDiskNumber returns N for "diskN..." names, or -1.
func macDiskNumber(name string) int {
	m := macWholeDiskRe.FindStringSubmatch(name)
	if m == nil {
		return -1
	}
	n, err := strconv.ParseUint(m[1], 10, 31)
	if err != nil {
		return -1
	}
	return int(n)
}

// macSliceNumber returns the slice number of "diskNsM" names, or 0.
func macSliceNumber(name string) int {
	m := macSliceRe.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseUint(m[1], 10, 31)
	if err != nil {
		return 0
	}
	return int(n)
}

// plistMaps returns the dicts in a plist array, skipping anything else.
func plistMaps(v any) []map[string]any {
	items, _ := v.([]any)
	var out []map[string]any
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// plistString returns m[key] trimmed when it is a string, else "".
func plistString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// plistUint returns a non-negative plist number as uint64, else 0.
func plistUint(v any) uint64 {
	f, ok := shared.PlistNumber(v)
	if !ok {
		return 0
	}
	n, _ := shared.JSONUint64(f)
	return n
}
