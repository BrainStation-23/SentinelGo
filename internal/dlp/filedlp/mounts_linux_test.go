package filedlp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/dlp/policy"
)

const sampleMountinfo = `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
23 22 0:21 / /proc rw shared:12 - proc proc rw
24 22 0:5 / /dev rw shared:2 - devtmpfs udev rw
30 22 8:17 / /media/alice/KINGSTON rw,nosuid shared:40 - vfat /dev/sdb1 rw
31 22 8:33 / /media/alice/My\040Disk rw shared:41 - exfat /dev/sdc1 rw
32 22 253:0 / /media/alice/Secure rw shared:42 - ext4 /dev/mapper/luks-1 rw
33 22 179:1 / /media/alice/SDCARD rw shared:43 - vfat /dev/mmcblk0p1 rw
34 22 0:50 / /mnt/finance rw shared:44 - cifs //corp-fs/finance rw
35 22 0:51 / /mnt/nfs rw shared:45 - nfs4 files.example.com:/export rw
36 22 0:52 / /home/alice/remote rw shared:46 - fuse.sshfs alice@[fd00::1]:/srv rw
37 22 8:49 / /data rw shared:47 - ext4 /dev/sdd1 rw
38 22 0:60 / /run/user/1000 rw shared:48 - tmpfs tmpfs rw
39 22 8:18 / /boot/efi rw shared:49 - vfat /dev/sdb2 rw
bad line
`

// fakeSysfs builds /sys/dev/block links like the kernel's: a USB stick, a USB
// hard disk without the removable flag, a LUKS volume on USB, an SD card, an
// internal SATA disk and a disk with the removable flag on another bus.
func fakeSysfs(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	sysRoot, devRoot = filepath.Join(root, "sys"), filepath.Join(root, "dev")
	t.Cleanup(func() { sysRoot, devRoot = "/sys", "/dev" })
	usbDev := filepath.Join(sysRoot, "devices/pci0000:00/0000:00:14.0/usb2/2-1")
	devices := map[string]string{
		"8:17":  "devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb/sdb1",
		"8:18":  "devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb/sdb2",
		"8:33":  "devices/pci0000:00/0000:00:14.0/usb3/3-1/3-1:1.0/host7/target7:0:0/7:0:0:0/block/sdc/sdc1",
		"8:2":   "devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda2",
		"8:49":  "devices/pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0/block/sdd/sdd1",
		"253:0": "devices/virtual/block/dm-0",
		"179:1": "devices/platform/mmc_host/mmc0/mmc0:0001/block/mmcblk0/mmcblk0p1",
	}
	for majmin, rel := range devices {
		full := filepath.Join(sysRoot, rel)
		mustMkdir(t, full)
		mustLink(t, full, filepath.Join(sysRoot, "dev/block", majmin))
	}
	mustWrite(t, filepath.Join(usbDev, "idVendor"), "0951\n")
	mustWrite(t, filepath.Join(usbDev, "idProduct"), "1666\n")
	mustWrite(t, filepath.Join(usbDev, "serial"), "S1\n")
	// dm-0 sits on sdc1 (USB).
	mustWrite(t, filepath.Join(sysRoot, "devices/virtual/block/dm-0/slaves/sdc1/dev"), "8:33\n")
	// sdd has the removable flag (e.g. a hot-swap bay) though it's on ATA.
	mustWrite(t, filepath.Join(sysRoot, devices["8:49"], "..", "removable"), "1\n")
	mustWrite(t, filepath.Join(sysRoot, devices["8:2"], "..", "removable"), "0\n")
	mustMkdir(t, filepath.Join(devRoot, "disk/by-label"))
	mustLink(t, "../../sdb1", filepath.Join(devRoot, "disk/by-label", `KINGSTON\x20USB`))
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustLink(t *testing.T, target, link string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(link))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestParseMountinfo(t *testing.T) {
	ms := parseMountinfo(strings.NewReader(sampleMountinfo))
	if len(ms) != 13 {
		t.Fatalf("%d mounts", len(ms))
	}
	if ms[4].MountPoint != "/media/alice/My Disk" || ms[4].FSType != "exfat" || ms[4].MajMin != "8:33" {
		t.Errorf("escaped mount %+v", ms[4])
	}
	if ms[7].Source != "//corp-fs/finance" || ms[7].ID != 34 || ms[7].FSType != "cifs" {
		t.Errorf("cifs %+v", ms[7])
	}
}

func TestClassify(t *testing.T) {
	fakeSysfs(t)
	labels := volumeLabels()
	got := map[string]Destination{}
	for _, m := range parseMountinfo(strings.NewReader(sampleMountinfo)) {
		if d, ok := classify(m, labels); ok {
			got[m.MountPoint] = d
		}
	}
	want := map[string]struct {
		channel, host, label, vendor string
	}{
		"/media/alice/KINGSTON": {policy.ChannelFileRemovable, "", "KINGSTON USB", "0951"},
		"/media/alice/My Disk":  {policy.ChannelFileRemovable, "", "", ""}, // a USB disk without the removable flag
		"/media/alice/Secure":   {policy.ChannelFileRemovable, "", "", ""}, // LUKS on USB
		"/media/alice/SDCARD":   {policy.ChannelFileRemovable, "", "", ""},
		"/data":                 {policy.ChannelFileRemovable, "", "", ""}, // removable flag
		"/mnt/finance":          {policy.ChannelFileNetworkShare, "corp-fs", "", ""},
		"/mnt/nfs":              {policy.ChannelFileNetworkShare, "files.example.com", "", ""},
		"/home/alice/remote":    {policy.ChannelFileNetworkShare, "fd00::1", "", ""},
	}
	for mp, w := range want {
		d, ok := got[mp]
		if !ok {
			t.Errorf("%s not classified", mp)
			continue
		}
		vendor := ""
		if d.USB != nil {
			vendor = d.USB.VendorID
		}
		if d.Channel != w.channel || d.ShareHost != w.host || d.VolumeLabel != w.label || vendor != w.vendor || d.Mount != mp {
			t.Errorf("%s: %+v", mp, d)
		}
	}
	for _, mp := range []string{"/", "/proc", "/dev", "/run/user/1000", "/boot/efi"} {
		if _, ok := got[mp]; ok {
			t.Errorf("%s classified as a destination", mp)
		}
	}
	if len(got) != len(want) {
		t.Errorf("classified %d mounts, want %d: %v", len(got), len(want), got)
	}
	if usb := got["/media/alice/KINGSTON"].USB; usb == nil || usb.ProductID != "1666" || usb.Serial != "S1" {
		t.Errorf("usb ids %+v", usb)
	}
}

func TestShareHost(t *testing.T) {
	for _, tc := range [][3]string{
		{"cifs", "//host/share", "host"},
		{"cifs", "//10.0.0.5/share/sub", "10.0.0.5"},
		{"nfs", "nas:/vol/a", "nas"},
		{"fuse.sshfs", "bob@server:/home/bob", "server"},
		{"fuse.sshfs", "server:", "server"},
		{"fuse.sshfs", "alice@[fd00::1]:/srv", "fd00::1"},
		{"nfs", "[2001:db8::5]:/export", "2001:db8::5"},
		{"cifs", "weird", ""},
	} {
		if got := shareHost(tc[0], tc[1]); got != tc[2] {
			t.Errorf("shareHost(%s, %s) = %s", tc[0], tc[1], got)
		}
	}
}

func TestProcessInfo(t *testing.T) {
	root := t.TempDir()
	procRoot = root
	t.Cleanup(func() { procRoot = "/proc" })
	dir := filepath.Join(root, "1234")
	mustWrite(t, filepath.Join(dir, "comm"), "cp\n")
	mustWrite(t, filepath.Join(dir, "status"), "Name:\tcp\nUid:\t0\t0\t0\t0\n")
	mustLink(t, "/usr/bin/cp (deleted)", filepath.Join(dir, "exe"))
	p := processInfo(1234)
	if p.Name != "cp" || p.Exe != "/usr/bin/cp" || p.UID != "0" || p.User != "root" || p.PID != 1234 {
		t.Errorf("%+v", p)
	}
	if p := processInfo(9999); p.PID != 9999 || p.Name != "" || p.User != "" {
		t.Errorf("gone process %+v", p)
	}
}

func TestIsMajMin(t *testing.T) {
	for s, want := range map[string]bool{"8:17": true, "253:0": true, "8": false, ":1": false, "8:": false, "../x:1": false, "8:1/../..": false} {
		if isMajMin(s) != want {
			t.Errorf("isMajMin(%q) != %v", s, want)
		}
	}
	if ok, _, _ := blockDevice("../../etc:1"); ok {
		t.Error("a bad device number was followed")
	}
}
