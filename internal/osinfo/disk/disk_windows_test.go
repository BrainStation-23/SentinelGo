package disk

import (
	"testing"
)

func TestWindowsDriveType(t *testing.T) {
	// Get-PhysicalDisk returns MediaType and BusType as strings, not integers.
	cases := []struct {
		mediaType string
		busType   string
		want      string
	}{
		{"HDD", "SATA", "HDD"},
		{"HDD", "", "HDD"},
		{"SSD", "SATA", "SSD"},
		{"SSD", "NVMe", "NVMe"}, // BusType NVMe takes precedence over generic SSD
		{"SSD", "nvme", "NVMe"}, // case-insensitive
		{"SSD", "", "SSD"},
		{"SCM", "", "SCM"},
		{"Unspecified", "NVMe", "NVMe"}, // unknown media but NVMe bus
		{"Unspecified", "SATA", "Unknown"},
		{"", "", "Unknown"},
	}
	for _, c := range cases {
		got := windowsDriveType(c.mediaType, c.busType)
		if got != c.want {
			t.Errorf("windowsDriveType(%q, %q) = %q, want %q", c.mediaType, c.busType, got, c.want)
		}
	}
}

func TestWindowsInterfaceType(t *testing.T) {
	// BusType is a string from Get-PhysicalDisk ("NVMe", "SATA", etc.).
	cases := []struct {
		busType string
		want    string
	}{
		{"NVMe", "NVMe"},
		{"nvme", "NVMe"},
		{"SATA", "SATA"},
		{"SAS", "SAS"},
		{"SCSI", "SCSI"},
		{"USB", "USB"},
		{"ATA", "ATA"},
		{"ATAPI", "ATAPI"},
		{"IEEE1394", "IEEE1394"},
		{"RAID", "RAID"},
		{"iSCSI", "iSCSI"},
		{"SD", "SD"},
		{"MMC", "MMC"},
		{"Virtual", "Virtual"},
		{"FileBackedVirtual", "Virtual"},
		{"Spaces", "Spaces"},
		{"SCM", "SCM"},
		{"", "Unknown"},
		{"Thunderbolt", "Thunderbolt"}, // unknown passed through as-is
	}
	for _, c := range cases {
		got := windowsInterfaceType(c.busType)
		if got != c.want {
			t.Errorf("windowsInterfaceType(%q) = %q, want %q", c.busType, got, c.want)
		}
	}
}

func TestWindowsHealthStatus(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Healthy", "Healthy"},
		{"healthy", "Healthy"},
		{"HEALTHY", "Healthy"},
		{"  Healthy  ", "Healthy"},
		{"Warning", "Warning"},
		{"warning", "Warning"},
		{"Unhealthy", "Unhealthy"},
		{"unhealthy", "Unhealthy"},
		{"", "Unknown"},
		{"Unknown", "Unknown"},
	}
	for _, c := range cases {
		got := windowsHealthStatus(c.input)
		if got != c.want {
			t.Errorf("windowsHealthStatus(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// TestGetDisks_Integration calls the real Get() which shells out to PowerShell.
// Run with: go test ./internal/osinfo/disk/ (omit -short to execute).
func TestGetDisks_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real disk collection (shells out to PowerShell) in -short mode")
	}
	disks := Get()
	if len(disks) == 0 {
		t.Fatal("Get() returned no disks")
	}
	for i, d := range disks {
		if d.Capacity == 0 {
			t.Errorf("disks[%d].Capacity is 0", i)
		}
		if d.Description == "" {
			t.Errorf("disks[%d].Description is empty", i)
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
		t.Logf("disk[%d]: %s | type=%s iface=%s health=%s enc=%s/%s drive=%s fs=%s",
			i, d.Description, d.DriveType, d.InterfaceType, d.HealthStatus,
			d.EncryptionStatus, d.EncryptionType, d.DriveLetter, d.FileSystem)
	}
}
