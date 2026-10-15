//go:build linux

package disk

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// Recorded `lsblk -J -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID,PARTTYPENAME,PARTN`
// output (util-linux 2.41 shape).
const (
	// Ubuntu with full-disk encryption: EFI, /boot, then LUKS holding LVM with
	// the root file system. A second, unencrypted data disk.
	lsblkLUKSInstall = `{"blockdevices":[
	{"name":"nvme0n1","type":"disk","size":512110190592,"fstype":null,"mountpoint":null,"label":null,"uuid":null,"parttypename":null,"partn":null,
	 "children":[
	  {"name":"nvme0n1p1","type":"part","size":1127219200,"fstype":"vfat","mountpoint":"/boot/efi","label":null,"uuid":"8F2A-1C3B","parttypename":"EFI System","partn":1},
	  {"name":"nvme0n1p2","type":"part","size":2147483648,"fstype":"ext4","mountpoint":"/boot","label":null,"uuid":"0b1c2d3e-0000-4000-8000-000000000002","parttypename":"Linux filesystem","partn":2},
	  {"name":"nvme0n1p3","type":"part","size":508833300480,"fstype":"crypto_LUKS","mountpoint":null,"label":null,"uuid":"0b1c2d3e-0000-4000-8000-000000000003","parttypename":"Linux filesystem","partn":3,
	   "children":[
	    {"name":"dm_crypt-0","type":"crypt","size":508816523264,"fstype":"LVM2_member","mountpoint":null,"label":null,"uuid":"lvm-pv-uuid","parttypename":null,"partn":null,
	     "children":[
	      {"name":"ubuntu--vg-ubuntu--lv","type":"lvm","size":508812328960,"fstype":"ext4","mountpoint":"/","label":null,"uuid":"0b1c2d3e-0000-4000-8000-0000000000aa","parttypename":null,"partn":null}
	     ]}
	   ]}
	 ]},
	{"name":"sda","type":"disk","size":2000398934016,"fstype":null,"mountpoint":null,"label":null,"uuid":null,"parttypename":null,"partn":null,
	 "children":[
	  {"name":"sda1","type":"part","size":2000397795328,"fstype":"ext4","mountpoint":"/data","label":"data","uuid":"0b1c2d3e-0000-4000-8000-0000000000d1","parttypename":"Linux filesystem","partn":1}
	 ]},
	{"name":"loop0","type":"loop","size":4096,"fstype":"squashfs","mountpoint":"/snap/bare/5","label":null,"uuid":null,"parttypename":null,"partn":null}
]}`

	// Older util-linux without PARTTYPENAME/PARTN, sizes as strings, a locked
	// LUKS partition (no mapper child) and swap.
	lsblkBasicColumns = `{"blockdevices":[
	{"name":"sda","type":"disk","size":"256060514304","fstype":null,"mountpoint":null,"label":null,"uuid":null,
	 "children":[
	  {"name":"sda1","type":"part","size":"536870912","fstype":"vfat","mountpoint":"/boot/efi","label":null,"uuid":"AAAA-BBBB"},
	  {"name":"sda2","type":"part","size":"200000000000","fstype":"ext4","mountpoint":"/","label":null,"uuid":"root-uuid"},
	  {"name":"sda3","type":"part","size":"40000000000","fstype":"crypto_LUKS","mountpoint":null,"label":null,"uuid":"vault-uuid"},
	  {"name":"sda4","type":"part","size":"8000000000","fstype":"swap","mountpoint":"[SWAP]","label":null,"uuid":"swap-uuid"},
	  {"name":"sda5","type":"part","size":"1048576","fstype":null,"mountpoint":null,"label":null,"uuid":null}
	 ]}
]}`

	// LUKS on the whole disk: no partitions at all.
	lsblkWholeDiskLUKS = `{"blockdevices":[
	{"name":"sdb","type":"disk","size":1000204886016,"fstype":"crypto_LUKS","mountpoint":null,"label":null,"uuid":"whole-uuid","parttypename":null,"partn":null,
	 "children":[{"name":"backup","type":"crypt","size":1000188108800,"fstype":"ext4","mountpoint":"/backup","label":null,"uuid":"inner-uuid","parttypename":null,"partn":null}]}
]}`
)

func TestParseLinuxDiskLayouts_LUKSInstall(t *testing.T) {
	layouts := parseLinuxDiskLayouts(lsblkLUKSInstall)
	if len(layouts) != 2 {
		t.Fatalf("got %d disks, want 2 (loop devices skipped): %v", len(layouts), layouts)
	}
	nvme := layouts["nvme0n1"]
	if len(nvme.partitions) != 3 {
		t.Fatalf("nvme0n1: got %d partitions, want 3", len(nvme.partitions))
	}
	efi, boot, root := nvme.partitions[0], nvme.partitions[1], nvme.partitions[2]
	if !efi.IsSystem || efi.EncryptionState != encStateNone || efi.MountPoint != "/boot/efi" || efi.PartitionType != "EFI System" {
		t.Errorf("EFI = %+v", efi)
	}
	if boot.IsBoot || boot.EncryptionState != encStateNone || boot.PartitionNumber != 2 {
		t.Errorf("/boot = %+v", boot)
	}
	if root.EncryptionState != encStateFull || root.EncryptionProvider != "LUKS" || !root.IsBoot ||
		root.MountPoint != "/" || root.FileSystem != "ext4" || root.VolumeGUID != "0b1c2d3e-0000-4000-8000-000000000003" ||
		root.SizeBytes != 508833300480 || root.PartitionNumber != 3 {
		t.Errorf("LUKS root = %+v", root)
	}
	if nvme.mountPoint != "/" || nvme.fileSystem != "ext4" || !nvme.luks {
		t.Errorf("nvme0n1 primary = %q %q luks=%v", nvme.fileSystem, nvme.mountPoint, nvme.luks)
	}
	if s, typ := linuxEncryptionStatus("/dev/nvme0n1", nvme); s != "enabled" || typ != "software" {
		t.Errorf("nvme0n1 encryption = %s/%s, want enabled/software", s, typ)
	}

	sda := layouts["sda"]
	if len(sda.partitions) != 1 || sda.partitions[0].EncryptionState != encStateNone || sda.partitions[0].VolumeLabel != "data" {
		t.Errorf("sda = %+v", sda.partitions)
	}
	if sda.luks || sda.mountPoint != "/data" {
		t.Errorf("sda primary = %q luks=%v", sda.mountPoint, sda.luks)
	}
	if s, _ := summarizeDiskEncryption(sda.partitions); s != "disabled" {
		t.Errorf("sda status = %s, want disabled", s)
	}
}

func TestParseLinuxDiskLayouts_BasicColumns(t *testing.T) {
	sda := parseLinuxDiskLayouts(lsblkBasicColumns)["sda"]
	want := []struct {
		number int
		state  string
		mount  string
	}{
		{1, encStateNone, "/boot/efi"},
		{2, encStateNone, "/"},
		{3, encStateFull, ""}, // locked LUKS
		{4, encStateNone, ""}, // swap isn't a mount point
		{5, encStateUnknown, ""},
	}
	if len(sda.partitions) != len(want) {
		t.Fatalf("got %d partitions, want %d", len(sda.partitions), len(want))
	}
	for i, w := range want {
		p := sda.partitions[i]
		if p.PartitionNumber != w.number || p.EncryptionState != w.state || p.MountPoint != w.mount {
			t.Errorf("sda%d = number %d state %q mount %q, want %d %q %q", i+1, p.PartitionNumber, p.EncryptionState, p.MountPoint, w.number, w.state, w.mount)
		}
	}
	if sda.partitions[0].SizeBytes != 536870912 || !sda.partitions[0].IsSystem {
		t.Errorf("sda1 = %+v", sda.partitions[0])
	}
	if sda.partitions[2].FileSystem != "crypto_LUKS" || sda.partitions[2].EncryptionProvider != "LUKS" {
		t.Errorf("locked LUKS = %+v", sda.partitions[2])
	}
	// The root file system decides: unencrypted, though another partition is
	// a LUKS vault.
	if !sda.luks {
		t.Error("luks = false, want true for the LUKS vault")
	}
	if s, typ := linuxEncryptionStatus("/dev/sda", sda); s != "disabled" || typ != "none" {
		t.Errorf("encryption = %s/%s, want disabled/none", s, typ)
	}
}

func TestParseLinuxDiskLayouts_WholeDiskLUKS(t *testing.T) {
	sdb := parseLinuxDiskLayouts(lsblkWholeDiskLUKS)["sdb"]
	if sdb.partitions == nil || len(sdb.partitions) != 0 {
		t.Errorf("partitions = %v, want an empty array", sdb.partitions)
	}
	if !sdb.luks || sdb.mountPoint != "/backup" || sdb.fileSystem != "ext4" {
		t.Errorf("sdb = %+v", sdb)
	}
	if s, typ := linuxEncryptionStatus("/dev/sdb", sdb); s != "enabled" || typ != "software" {
		t.Errorf("encryption = %s/%s, want enabled/software", s, typ)
	}
}

// TestLinuxEncryptionStatus_WholeDiskFS covers a disk formatted with no
// partition table, as on WSL and many VMs.
func TestLinuxEncryptionStatus_WholeDiskFS(t *testing.T) {
	l := parseLinuxDiskLayouts(`{"blockdevices":[{"name":"sdd","type":"disk","size":1099511627776,"fstype":"ext4","mountpoint":"/mnt/wslg/distro"}]}`)["sdd"]
	if s, typ := linuxEncryptionStatus("/dev/sdd", l); s != "disabled" || typ != "none" {
		t.Errorf("encryption = %s/%s, want disabled/none", s, typ)
	}
	if s, _ := linuxEncryptionStatus("/dev/sdx", linuxDiskLayout{partitions: []shared.DiskPartition{}}); s != "unknown" {
		t.Errorf("no data = %s, want unknown", s)
	}
}

func TestLinuxPartitionNumber(t *testing.T) {
	cases := []struct {
		node lsblkNode
		want int
	}{
		{lsblkNode{Name: "sda1"}, 1},
		{lsblkNode{Name: "nvme0n1p12"}, 12},
		{lsblkNode{Name: "mmcblk0p2"}, 2},
		{lsblkNode{Name: "sda1", PartN: 7.0}, 7},
		{lsblkNode{Name: "sda1", PartN: "9"}, 9},
		{lsblkNode{Name: "sda1", PartN: -1.0}, 1},
		{lsblkNode{Name: "sda99999999999999999999"}, 0},
		{lsblkNode{Name: "weird"}, 0},
		{lsblkNode{}, 0},
	}
	for _, c := range cases {
		if got := linuxPartitionNumber(c.node); got != c.want {
			t.Errorf("linuxPartitionNumber(%+v) = %d, want %d", c.node, got, c.want)
		}
	}
}

func TestParseLinuxDiskLayouts_Malformed(t *testing.T) {
	for _, s := range []string{"", "{", "null", `{"blockdevices":null}`, `{"blockdevices":[{"type":"disk"}]}`} {
		for name, l := range parseLinuxDiskLayouts(s) {
			t.Errorf("input %q produced disk %q: %+v", s, name, l)
		}
	}
	var none []shared.DiskPartition
	if s, _ := summarizeDiskEncryption(none); s != "unknown" {
		t.Errorf("no partitions = %s, want unknown", s)
	}
}
