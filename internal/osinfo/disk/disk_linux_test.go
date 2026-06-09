package disk

import (
	"testing"
)

func TestLinuxDriveType(t *testing.T) {
	cases := []struct {
		name string
		rota bool
		want string
	}{
		{"nvme0n1", false, "NVMe"}, // NVMe device name takes priority over rota
		{"nvme1n1", true, "NVMe"},  // even if rota is somehow true, name wins
		{"sda", false, "SSD"},
		{"sdb", false, "SSD"},
		{"sda", true, "HDD"},
		{"vda", true, "HDD"},  // virtual HDD
		{"vda", false, "SSD"}, // virtual SSD
		{"mmcblk0", false, "SSD"},
		{"mmcblk0", true, "HDD"},
	}
	for _, c := range cases {
		got := linuxDriveType(c.name, c.rota)
		if got != c.want {
			t.Errorf("linuxDriveType(%q, %v) = %q, want %q", c.name, c.rota, got, c.want)
		}
	}
}

func TestLinuxInterfaceType(t *testing.T) {
	cases := []struct {
		tran string
		want string
	}{
		{"nvme", "NVMe"},
		{"NVME", "NVMe"},
		{"sata", "SATA"},
		{"SATA", "SATA"},
		{"usb", "USB"},
		{"sas", "SAS"},
		{"ata", "ATA"},
		{"mmc", "MMC"},
		{"", "Unknown"},
		{"pcie", "PCIE"}, // unknown type returned uppercased
		{"scsi", "SCSI"},
	}
	for _, c := range cases {
		got := linuxInterfaceType(c.tran)
		if got != c.want {
			t.Errorf("linuxInterfaceType(%q) = %q, want %q", c.tran, got, c.want)
		}
	}
}

// TestGetDisks_Integration calls the real Get() which shells out to lsblk and smartctl.
// Run with: go test ./internal/osinfo/disk/ (omit -short to execute).
func TestGetDisks_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real disk collection (shells out to lsblk/smartctl) in -short mode")
	}
	disks := Get()
	if len(disks) == 0 {
		t.Fatal("Get() returned no disks")
	}
	for i, d := range disks {
		if d.Capacity == 0 {
			t.Errorf("disks[%d].Capacity is 0", i)
		}
		if d.DriveType == "" {
			t.Errorf("disks[%d].DriveType is empty", i)
		}
		if d.HealthStatus == "" {
			t.Errorf("disks[%d].HealthStatus is empty", i)
		}
		if d.InterfaceType == "" {
			t.Errorf("disks[%d].InterfaceType is empty", i)
		}
		if d.EncryptionStatus == "" {
			t.Errorf("disks[%d].EncryptionStatus is empty", i)
		}
		t.Logf("disk[%d]: %s | type=%s iface=%s health=%s enc=%s/%s mount=%s fs=%s",
			i, d.Description, d.DriveType, d.InterfaceType, d.HealthStatus,
			d.EncryptionStatus, d.EncryptionType, d.MountPoint, d.FileSystem)
	}
}
