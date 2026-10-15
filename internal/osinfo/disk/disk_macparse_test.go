package disk

import (
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// Recorded `diskutil list -plist` output from an Apple Silicon Mac, trimmed
// to the keys the parser reads. disk0 is the internal SSD; disk3 is the
// synthesized APFS container on disk0s2 holding the system and data volumes,
// and disk2 the recovery container on disk0s3.
const macDiskutilList = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AllDisks</key>
	<array><string>disk0</string><string>disk0s1</string><string>disk0s2</string><string>disk0s3</string><string>disk2</string><string>disk3</string></array>
	<key>AllDisksAndPartitions</key>
	<array>
		<dict>
			<key>Content</key><string>GUID_partition_scheme</string>
			<key>DeviceIdentifier</key><string>disk0</string>
			<key>OSInternal</key><false/>
			<key>Partitions</key>
			<array>
				<dict>
					<key>Content</key><string>Apple_APFS_ISC</string>
					<key>DeviceIdentifier</key><string>disk0s1</string>
					<key>DiskUUID</key><string>A1A1A1A1-0000-4000-8000-000000000001</string>
					<key>Size</key><integer>524288000</integer>
				</dict>
				<dict>
					<key>Content</key><string>Apple_APFS</string>
					<key>DeviceIdentifier</key><string>disk0s2</string>
					<key>DiskUUID</key><string>A1A1A1A1-0000-4000-8000-000000000002</string>
					<key>Size</key><integer>494384795648</integer>
				</dict>
				<dict>
					<key>Content</key><string>Apple_APFS_Recovery</string>
					<key>DeviceIdentifier</key><string>disk0s3</string>
					<key>DiskUUID</key><string>A1A1A1A1-0000-4000-8000-000000000003</string>
					<key>Size</key><integer>5368664064</integer>
				</dict>
			</array>
			<key>Size</key><integer>500277790720</integer>
		</dict>
		<dict>
			<key>APFSPhysicalStores</key>
			<array><dict><key>DeviceIdentifier</key><string>disk0s3</string></dict></array>
			<key>APFSVolumes</key>
			<array>
				<dict>
					<key>DeviceIdentifier</key><string>disk2s1</string>
					<key>OSInternal</key><true/>
					<key>Size</key><integer>5368664064</integer>
					<key>VolumeName</key><string>Recovery</string>
					<key>VolumeUUID</key><string>C2C2C2C2-0000-4000-8000-000000000001</string>
				</dict>
			</array>
			<key>Content</key><string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
			<key>DeviceIdentifier</key><string>disk2</string>
			<key>OSInternal</key><true/>
			<key>Partitions</key><array/>
			<key>Size</key><integer>5368664064</integer>
		</dict>
		<dict>
			<key>APFSPhysicalStores</key>
			<array><dict><key>DeviceIdentifier</key><string>disk0s2</string></dict></array>
			<key>APFSVolumes</key>
			<array>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s1</string>
					<key>DiskUUID</key><string>D3D3D3D3-0000-4000-8000-000000000001</string>
					<key>MountedSnapshots</key>
					<array>
						<dict>
							<key>Sealed</key><string>Yes</string>
							<key>SnapshotBSD</key><string>disk3s1s1</string>
							<key>SnapshotMountPoint</key><string>/</string>
							<key>SnapshotName</key><string>com.apple.os.update-0123</string>
						</dict>
					</array>
					<key>OSInternal</key><false/>
					<key>Size</key><integer>494384795648</integer>
					<key>VolumeName</key><string>Macintosh HD</string>
					<key>VolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A1</string>
				</dict>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s5</string>
					<key>DiskUUID</key><string>D3D3D3D3-0000-4000-8000-000000000005</string>
					<key>MountPoint</key><string>/System/Volumes/Data</string>
					<key>OSInternal</key><false/>
					<key>Size</key><integer>494384795648</integer>
					<key>VolumeName</key><string>Data</string>
					<key>VolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A5</string>
				</dict>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s2</string>
					<key>MountPoint</key><string>/System/Volumes/Preboot</string>
					<key>OSInternal</key><true/>
					<key>VolumeName</key><string>Preboot</string>
					<key>VolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A2</string>
				</dict>
			</array>
			<key>Content</key><string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
			<key>DeviceIdentifier</key><string>disk3</string>
			<key>OSInternal</key><false/>
			<key>Partitions</key><array/>
			<key>Size</key><integer>494384795648</integer>
		</dict>
	</array>
	<key>VolumesFromDisks</key><array><string>Macintosh HD</string><string>Data</string></array>
	<key>WholeDisks</key><array><string>disk0</string><string>disk2</string><string>disk3</string></array>
</dict>
</plist>
`

// macAPFSList returns recorded `diskutil apfs list -plist` output for the
// same Mac, with the Data volume's FileVault flags set by dataFlags.
func macAPFSList(dataFlags string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Containers</key>
	<array>
		<dict>
			<key>APFSContainerUUID</key><string>C2C2C2C2-0000-4000-8000-000000000000</string>
			<key>CapacityCeiling</key><integer>5368664064</integer>
			<key>CapacityFree</key><integer>3700000000</integer>
			<key>ContainerReference</key><string>disk2</string>
			<key>PhysicalStores</key>
			<array><dict><key>DeviceIdentifier</key><string>disk0s3</string><key>Size</key><integer>5368664064</integer></dict></array>
			<key>Volumes</key>
			<array>
				<dict>
					<key>APFSVolumeUUID</key><string>C2C2C2C2-0000-4000-8000-000000000001</string>
					<key>CapacityInUse</key><integer>1600000000</integer>
					<key>CryptoMigrationOn</key><false/>
					<key>DeviceIdentifier</key><string>disk2s1</string>
					<key>Encryption</key><false/>
					<key>FileVault</key><false/>
					<key>Locked</key><false/>
					<key>Name</key><string>Recovery</string>
					<key>Roles</key><array><string>Recovery</string></array>
				</dict>
			</array>
		</dict>
		<dict>
			<key>APFSContainerUUID</key><string>D3D3D3D3-0000-4000-8000-000000000000</string>
			<key>CapacityCeiling</key><integer>494384795648</integer>
			<key>CapacityFree</key><integer>250000000000</integer>
			<key>ContainerReference</key><string>disk3</string>
			<key>PhysicalStores</key>
			<array><dict><key>DeviceIdentifier</key><string>disk0s2</string><key>Size</key><integer>494384795648</integer></dict></array>
			<key>Volumes</key>
			<array>
				<dict>
					<key>APFSVolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A1</string>
					<key>CapacityInUse</key><integer>11000000000</integer>
					<key>CryptoMigrationOn</key><false/>
					<key>DeviceIdentifier</key><string>disk3s1</string>
					<key>Encryption</key><true/>
					<key>FileVault</key><true/>
					<key>Locked</key><false/>
					<key>Name</key><string>Macintosh HD</string>
					<key>Roles</key><array><string>System</string></array>
				</dict>
				<dict>
					<key>APFSVolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A5</string>
					<key>CapacityInUse</key><integer>220000000000</integer>
					<key>DeviceIdentifier</key><string>disk3s5</string>
					` + dataFlags + `
					<key>Name</key><string>Data</string>
					<key>Roles</key><array><string>Data</string></array>
				</dict>
				<dict>
					<key>APFSVolumeUUID</key><string>D3D3D3D3-0000-4000-8000-0000000000A2</string>
					<key>DeviceIdentifier</key><string>disk3s2</string>
					<key>Name</key><string>Preboot</string>
					<key>Roles</key><array><string>Preboot</string></array>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>
`
}

const (
	macDataFileVaultOn  = `<key>CryptoMigrationOn</key><false/><key>Encryption</key><true/><key>FileVault</key><true/><key>Locked</key><false/>`
	macDataFileVaultOff = `<key>CryptoMigrationOn</key><false/><key>Encryption</key><false/><key>FileVault</key><false/><key>Locked</key><false/>`
	macDataEncrypting   = `<key>CryptoMigrationOn</key><true/><key>Encryption</key><true/><key>FileVault</key><true/><key>Locked</key><false/>`
)

func decodeMacLayout(t *testing.T, list, apfs, fdesetup string) macLayout {
	t.Helper()
	l, ok := shared.PlistFromOutput(list)
	if !ok {
		t.Fatal("diskutil list fixture doesn't decode")
	}
	var a any
	if apfs != "" {
		if a, ok = shared.PlistFromOutput(apfs); !ok {
			t.Fatal("diskutil apfs list fixture doesn't decode")
		}
	}
	return parseMacLayout(l, a, fdesetup)
}

func TestParseMacLayout_FileVaultOn(t *testing.T) {
	layout := decodeMacLayout(t, macDiskutilList, macAPFSList(macDataFileVaultOn), "FileVault is On.\n")
	if len(layout.partitions) != 1 {
		t.Fatalf("got disks %v, want only the physical disk0", keys(layout.partitions))
	}
	parts := layout.partitions["disk0"]
	// disk0s1 (no container in the APFS list) stays a partition; disk0s2 and
	// disk0s3 expand into their containers' volumes.
	want := []struct {
		label, typ, mount, state string
		boot                     bool
	}{
		{"", "Apple_APFS_ISC", "", encStateUnknown, false},
		{"Macintosh HD", "APFS System", "/", encStateFull, true},
		{"Data", "APFS Data", "/System/Volumes/Data", encStateFull, false},
		{"Preboot", "APFS Preboot", "/System/Volumes/Preboot", encStateUnknown, false},
		{"Recovery", "APFS Recovery", "", encStateNone, false},
	}
	if len(parts) != len(want) {
		t.Fatalf("got %d partitions, want %d: %+v", len(parts), len(want), parts)
	}
	for i, w := range want {
		p := parts[i]
		if p.VolumeLabel != w.label || p.PartitionType != w.typ || p.MountPoint != w.mount || p.EncryptionState != w.state || p.IsBoot != w.boot {
			t.Errorf("parts[%d] = %q %q %q %q boot=%v, want %q %q %q %q boot=%v", i,
				p.VolumeLabel, p.PartitionType, p.MountPoint, p.EncryptionState, p.IsBoot,
				w.label, w.typ, w.mount, w.state, w.boot)
		}
		checkPartitionInvariants(t, p)
	}
	data := parts[2]
	if data.VolumeGUID != "D3D3D3D3-0000-4000-8000-0000000000A5" || data.PartitionNumber != 2 || data.FileSystem != "APFS" ||
		data.SizeBytes != 494384795648 || data.FreeBytes != 250000000000 || data.EncryptionProvider != "FileVault" {
		t.Errorf("Data = %+v", data)
	}
	if parts[0].VolumeGUID != "A1A1A1A1-0000-4000-8000-000000000001" || parts[0].SizeBytes != 524288000 {
		t.Errorf("disk0s1 = %+v", parts[0])
	}
	// Volumes take their physical partition's number: disk3 is on disk0s2 and
	// disk2 on disk0s3, so neither collides with disk0s1.
	for i, want := range []int{1, 2, 2, 2, 3} {
		if parts[i].PartitionNumber != want {
			t.Errorf("parts[%d].PartitionNumber = %d, want %d", i, parts[i].PartitionNumber, want)
		}
	}
	if got := layout.physicalDisk["disk3"]; got != "disk0" {
		t.Errorf("disk3 is on %q, want disk0", got)
	}
	if got := macPhysicalDiskFor("disk3s1s1", layout); got != "disk0" {
		t.Errorf("macPhysicalDiskFor(disk3s1s1) = %q, want disk0", got)
	}
	if got := macPhysicalDiskFor("disk7s1", layout); got != "disk7" {
		t.Errorf("macPhysicalDiskFor(disk7s1) = %q, want disk7", got)
	}
}

func TestParseMacLayout_Variants(t *testing.T) {
	cases := []struct {
		name, flags, fdesetup string
		wantState             string
		wantPct               float64 // -1: absent
	}{
		{"FileVault off", macDataFileVaultOff, "FileVault is Off.\n", encStateNone, -1},
		{"encrypting at 42%", macDataEncrypting, "FileVault is On.\nEncryption in progress: Percent completed = 42.0\n", encStateEncrypting, 42},
		{"decrypting", macDataEncrypting, "FileVault is Off.\nDecryption in progress: Percent completed = 58\n", encStateDecrypting, 58},
		{"locked", `<key>Locked</key><true/>`, "", encStateFull, -1},
		{"no flags", ``, "", encStateUnknown, -1},
		// Hardware encryption without FileVault (T2 / Apple Silicon): the key
		// isn't password-protected, so it isn't reported as encrypted.
		{"encrypted at rest without FileVault", `<key>Encryption</key><true/><key>FileVault</key><false/>`, "FileVault is Off.", encStateNone, -1},
		{"Encryption flag only", `<key>Encryption</key><true/>`, "", encStateFull, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parts := decodeMacLayout(t, macDiskutilList, macAPFSList(c.flags), c.fdesetup).partitions["disk0"]
			var data *shared.DiskPartition
			for i := range parts {
				if parts[i].VolumeLabel == "Data" {
					data = &parts[i]
				}
			}
			if data == nil {
				t.Fatalf("no Data volume in %+v", parts)
			}
			if data.EncryptionState != c.wantState {
				t.Errorf("Data state = %q, want %q", data.EncryptionState, c.wantState)
			}
			switch {
			case c.wantPct < 0 && data.EncryptionPercentage != nil:
				t.Errorf("percentage = %v, want absent", *data.EncryptionPercentage)
			case c.wantPct >= 0 && (data.EncryptionPercentage == nil || *data.EncryptionPercentage != c.wantPct):
				t.Errorf("percentage = %v, want %v", data.EncryptionPercentage, c.wantPct)
			}
		})
	}
}

// TestParseMacLayout_NoAPFS covers `diskutil apfs list` failing: the physical
// partitions are still reported, with unknown encryption.
func TestParseMacLayout_NoAPFS(t *testing.T) {
	parts := decodeMacLayout(t, macDiskutilList, "", "").partitions["disk0"]
	if len(parts) != 3 {
		t.Fatalf("got %d partitions, want 3: %+v", len(parts), parts)
	}
	if parts[2].PartitionType != "Recovery" || parts[1].EncryptionState != encStateUnknown {
		t.Errorf("parts = %+v", parts)
	}
}

// TestParseMacLayout_IntelEFI covers an Intel Mac, whose EFI partition is a
// plain slice that is never encrypted.
func TestParseMacLayout_IntelEFI(t *testing.T) {
	list := strings.Replace(macDiskutilList,
		`<key>Content</key><string>Apple_APFS_ISC</string>`,
		`<key>Content</key><string>EFI</string><key>VolumeName</key><string>EFI</string><key>VolumeUUID</key><string>EFI-VOLUME-UUID</string>`, 1)
	efi := decodeMacLayout(t, list, macAPFSList(macDataFileVaultOn), "").partitions["disk0"][0]
	if efi.PartitionType != "EFI" || !efi.IsSystem || efi.EncryptionState != encStateNone || efi.VolumeGUID != "EFI-VOLUME-UUID" || efi.PartitionNumber != 1 {
		t.Errorf("EFI = %+v", efi)
	}
}

// TestParseMacLayout_EmptyContainer keeps the partition of an APFS container
// that has no volumes.
func TestParseMacLayout_EmptyContainer(t *testing.T) {
	apfs := `<plist version="1.0"><dict><key>Containers</key><array><dict>` +
		`<key>ContainerReference</key><string>disk3</string><key>CapacityCeiling</key><integer>494384795648</integer>` +
		`<key>PhysicalStores</key><array><dict><key>DeviceIdentifier</key><string>disk0s2</string></dict></array>` +
		`<key>Volumes</key><array/></dict></array></dict></plist>`
	parts := decodeMacLayout(t, macDiskutilList, apfs, "").partitions["disk0"]
	if len(parts) != 3 || parts[1].PartitionType != "Apple_APFS" || parts[1].PartitionNumber != 2 || parts[1].SizeBytes != 494384795648 {
		t.Errorf("parts = %+v, want disk0s2 kept as a partition", parts)
	}
}

func TestParseMacLayout_Malformed(t *testing.T) {
	for _, v := range []any{nil, "x", map[string]any{"AllDisksAndPartitions": "x"},
		map[string]any{"AllDisksAndPartitions": []any{nil, 1, map[string]any{"DeviceIdentifier": "notadisk"}}}} {
		l := parseMacLayout(v, v, "")
		if len(l.partitions) != 0 {
			t.Errorf("parseMacLayout(%v) = %v, want no disks", v, l.partitions)
		}
	}
}

func TestMacDiskAndSliceNumbers(t *testing.T) {
	cases := []struct {
		name         string
		disk, slice  int
		wantWholeDsk string
	}{
		{"disk0", 0, 0, "disk0"},
		{"disk3s5", 3, 5, "disk3"},
		{"disk3s1s1", 3, 1, "disk3"},
		{"disk12s3", 12, 3, "disk12"},
		{"", -1, 0, ""},
		{"/dev/disk0", -1, 0, ""},
		{"disk99999999999999999999", -1, 0, "disk99999999999999999999"},
	}
	for _, c := range cases {
		if got := macDiskNumber(c.name); got != c.disk {
			t.Errorf("macDiskNumber(%q) = %d, want %d", c.name, got, c.disk)
		}
		if got := macSliceNumber(c.name); got != c.slice {
			t.Errorf("macSliceNumber(%q) = %d, want %d", c.name, got, c.slice)
		}
		if got := macWholeDisk(c.name); got != c.wantWholeDsk {
			t.Errorf("macWholeDisk(%q) = %q, want %q", c.name, got, c.wantWholeDsk)
		}
	}
}

func keys(m map[string][]shared.DiskPartition) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
