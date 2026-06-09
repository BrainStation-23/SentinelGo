package disk

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestMacDriveType(t *testing.T) {
	cases := []struct {
		mediumType string
		protocol   string
		want       string
	}{
		{"SSD", "Apple Fabric", "NVMe"},      // Apple Silicon: Fabric bus = NVMe
		{"SSD", "apple fabric", "NVMe"},      // case-insensitive
		{"SSD", "PCI-Express", "NVMe"},       // Intel NVMe SSD
		{"SSD", "NVMe", "NVMe"},              // explicit NVMe protocol
		{"SSD", "SATA", "SSD"},               // SATA SSD
		{"SSD", "", "SSD"},                   // no protocol info
		{"Solid State Drive", "SATA", "SSD"}, // alternate spelling
		{"Hard Disk Drive", "SATA", "HDD"},
		{"Hard Disk Drive", "", "HDD"},
		{"", "SATA", "Unknown"},
		{"", "", "Unknown"},
		{"Flash Storage", "Apple Fabric", "Unknown"}, // unrecognised medium_type
	}
	for _, c := range cases {
		got := macDriveType(c.mediumType, c.protocol)
		if got != c.want {
			t.Errorf("macDriveType(%q, %q) = %q, want %q", c.mediumType, c.protocol, got, c.want)
		}
	}
}

func TestMacInterfaceType(t *testing.T) {
	cases := []struct {
		protocol string
		want     string
	}{
		{"Apple Fabric", "NVMe"},
		{"apple fabric", "NVMe"},
		{"NVMe", "NVMe"},
		{"nvme", "NVMe"},
		{"PCI-Express", "NVMe"},
		{"pci-express", "NVMe"},
		{"SATA", "SATA"},
		{"sata", "SATA"},
		{"USB", "USB"},
		{"USB 3.1", "USB"},
		{"Thunderbolt", "Thunderbolt"},
		{"Thunderbolt 3", "Thunderbolt"},
		{"", "Unknown"},
		{"FireWire", "FireWire"}, // unknown protocol returned as-is
	}
	for _, c := range cases {
		got := macInterfaceType(c.protocol)
		if got != c.want {
			t.Errorf("macInterfaceType(%q) = %q, want %q", c.protocol, got, c.want)
		}
	}
}

func TestMacHealthStatus(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Verified", "Healthy"},
		{"verified", "Healthy"},
		{"  Verified  ", "Healthy"},
		{"Failing", "Unhealthy"},
		{"failing", "Unhealthy"},
		{"Not Supported", "Unknown"},
		{"Not Available", "Unknown"},
		{"", "Unknown"},
		{"Unknown", "Unknown"},
	}
	for _, c := range cases {
		got := macHealthStatus(c.input)
		if got != c.want {
			t.Errorf("macHealthStatus(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestDeduplicateBySerial(t *testing.T) {
	d := func(serial, mount, desc string) shared.DiskDevice {
		return shared.DiskDevice{SerialNumber: serial, MountPoint: mount, Description: desc}
	}
	cases := []struct {
		name  string
		input []shared.DiskDevice
		want  []shared.DiskDevice
	}{
		{
			name:  "all unique serials",
			input: []shared.DiskDevice{d("A", "/", "disk0"), d("B", "/Volumes/X", "disk1")},
			want:  []shared.DiskDevice{d("A", "/", "disk0"), d("B", "/Volumes/X", "disk1")},
		},
		{
			name:  "two volumes same serial neither root",
			input: []shared.DiskDevice{d("A", "/System/Volumes/Data", "first"), d("A", "/System/Volumes/Update/mnt1", "second")},
			want:  []shared.DiskDevice{d("A", "/System/Volumes/Data", "first")},
		},
		{
			name:  "two volumes same serial second is root",
			input: []shared.DiskDevice{d("A", "/System/Volumes/Data", "data"), d("A", "/", "root")},
			want:  []shared.DiskDevice{d("A", "/", "root")},
		},
		{
			name:  "three volumes same serial root is middle",
			input: []shared.DiskDevice{d("A", "/System/Volumes/Update/mnt1", "snap"), d("A", "/", "root"), d("A", "/System/Volumes/Data", "data")},
			want:  []shared.DiskDevice{d("A", "/", "root")},
		},
		{
			name:  "empty serial kept as-is",
			input: []shared.DiskDevice{d("", "/Volumes/USB1", "usb"), d("", "/Volumes/USB2", "usb2")},
			want:  []shared.DiskDevice{d("", "/Volumes/USB1", "usb"), d("", "/Volumes/USB2", "usb2")},
		},
		{
			name:  "mix of empty and duplicate serials",
			input: []shared.DiskDevice{d("A", "/System/Volumes/Data", "data"), d("", "/Volumes/USB", "usb"), d("A", "/", "root")},
			want:  []shared.DiskDevice{d("A", "/", "root"), d("", "/Volumes/USB", "usb")},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deduplicateBySerial(c.input)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d; got %+v", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i].SerialNumber != c.want[i].SerialNumber ||
					got[i].MountPoint != c.want[i].MountPoint ||
					got[i].Description != c.want[i].Description {
					t.Errorf("entry[%d] = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestGetDisks_Integration calls the real Get() which shells out to system_profiler and fdesetup.
// Run with: go test ./internal/osinfo/disk/ (omit -short to execute).
func TestGetDisks_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real disk collection (shells out to system_profiler) in -short mode")
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
