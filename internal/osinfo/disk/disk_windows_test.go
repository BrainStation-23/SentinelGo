package disk

import (
	"encoding/json"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
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
		logPartitions(t, i, d)
	}
}

// Recorded windowsPartitionQuery output. winStandardInstall is a standard
// Windows 11 install (EFI, MSR, C:, Recovery) with C: BitLocker-encrypted;
// the rest are variations of it.
const (
	winStandardInstall = `{"BitLockerAvailable":true,"Partitions":[` +
		`{"PartitionNumber":1,"Type":"System","DriveLetter":"","AccessPaths":["\\\\?\\Volume{1ab32561-1d82-4e0f-9dfb-ea56c0fc88f2}\\"],"Size":209715200,"IsBoot":false,"IsSystem":true},` +
		`{"PartitionNumber":2,"Type":"Reserved","DriveLetter":"","AccessPaths":[],"Size":16777216,"IsBoot":false,"IsSystem":false},` +
		`{"PartitionNumber":3,"Type":"Basic","DriveLetter":"C","AccessPaths":["C:\\","\\\\?\\Volume{d1f7cd95-6fa0-4305-b0b0-14b8b9377b9c}\\"],"Size":2047248171008,"IsBoot":true,"IsSystem":false,"FileSystem":"NTFS","Label":"","FreeSpace":1571772039168,` +
		`"VolumeStatus":"FullyEncrypted","EncryptionPercentage":100,"EncryptionMethod":"XtsAes128","ProtectionStatus":"On",` +
		`"KeyProtectors":[{"Id":"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}","Type":"Tpm"},{"Id":"{11111111-2222-3333-4444-555555555555}","Type":"RecoveryPassword"}]},` +
		`{"PartitionNumber":4,"Type":"Recovery","DriveLetter":"","AccessPaths":["\\\\?\\Volume{5eed9f3d-20ef-47f5-af44-a956dc7c7921}\\"],"Size":931135488,"IsBoot":false,"IsSystem":false,"FileSystem":"NTFS","Label":"","FreeSpace":89317376}]}`

	// Windows Home: Get-BitLockerVolume isn't available.
	winHomeNoBitLocker = `{"BitLockerAvailable":false,"Partitions":[` +
		`{"PartitionNumber":1,"Type":"System","AccessPaths":["\\\\?\\Volume{1ab32561-1d82-4e0f-9dfb-ea56c0fc88f2}\\"],"Size":209715200,"IsSystem":true},` +
		`{"PartitionNumber":3,"Type":"Basic","DriveLetter":"C","AccessPaths":["C:\\"],"Size":2047248171008,"IsBoot":true,"FileSystem":"NTFS","FreeSpace":1571772039168}]}`

	// C: fully encrypted with protection suspended (e.g. during a Windows
	// update). Partitions and KeyProtectors are bare objects, the shape
	// ConvertTo-Json can give a one-element list.
	winSuspended = `{"BitLockerAvailable":true,"Partitions":` +
		`{"PartitionNumber":3,"Type":"Basic","DriveLetter":"C","AccessPaths":["C:\\"],"Size":2047248171008,"IsBoot":true,"FileSystem":"NTFS",` +
		`"VolumeStatus":"FullyEncrypted","EncryptionPercentage":100,"EncryptionMethod":"XtsAes256","ProtectionStatus":"Off","KeyProtectors":{"Id":"{AAAAAAAA-0000-0000-0000-000000000000}","Type":"RecoveryPassword"}}}`

	// C: encryption running, 42% done.
	winEncrypting42 = `{"BitLockerAvailable":true,"Partitions":[` +
		`{"PartitionNumber":3,"Type":"Basic","DriveLetter":"C","AccessPaths":["C:\\"],"Size":2047248171008,"IsBoot":true,"FileSystem":"NTFS",` +
		`"VolumeStatus":"EncryptionInProgress","EncryptionPercentage":42,"EncryptionMethod":"XtsAes128","ProtectionStatus":"Off","KeyProtectors":[]}]}`
)

func TestParseWindowsPartitions_StandardInstall(t *testing.T) {
	parts := parseWindowsPartitions(winStandardInstall)
	if len(parts) != 4 {
		t.Fatalf("got %d partitions, want 4: %+v", len(parts), parts)
	}
	wantTypes := []string{"EFI", "MSR", "Basic", "Recovery"}
	wantStates := []string{encStateNone, encStateNone, encStateFull, encStateNone}
	for i, p := range parts {
		if p.PartitionType != wantTypes[i] || p.EncryptionState != wantStates[i] {
			t.Errorf("parts[%d] = %s/%s, want %s/%s", i, p.PartitionType, p.EncryptionState, wantTypes[i], wantStates[i])
		}
		if p.PartitionNumber != i+1 {
			t.Errorf("parts[%d].PartitionNumber = %d, want %d", i, p.PartitionNumber, i+1)
		}
	}
	c := parts[2]
	if c.DriveLetter != "C" || c.MountPoint != "" || c.FileSystem != "NTFS" || !c.IsBoot || c.IsSystem {
		t.Errorf("C: = %+v", c)
	}
	if c.VolumeGUID != `\\?\Volume{d1f7cd95-6fa0-4305-b0b0-14b8b9377b9c}\` {
		t.Errorf("C: volume_guid = %q", c.VolumeGUID)
	}
	if c.SizeBytes != 2047248171008 || c.FreeBytes != 1571772039168 {
		t.Errorf("C: size/free = %d/%d", c.SizeBytes, c.FreeBytes)
	}
	if c.EncryptionProvider != "BitLocker" || c.EncryptionMethod != "XtsAes128" || c.ProtectionStatus != "on" {
		t.Errorf("C: provider/method/protection = %q/%q/%q", c.EncryptionProvider, c.EncryptionMethod, c.ProtectionStatus)
	}
	if c.KeyProtectorID != "{11111111-2222-3333-4444-555555555555}" {
		t.Errorf("C: key_protector_id = %q, want the RecoveryPassword protector's id", c.KeyProtectorID)
	}
	if strings.Join(c.KeyProtectorTypes, ",") != "Tpm,RecoveryPassword" {
		t.Errorf("C: key_protector_types = %v", c.KeyProtectorTypes)
	}
	if !parts[0].IsSystem || parts[0].DriveLetter != "" || parts[1].VolumeGUID != "" {
		t.Errorf("EFI/MSR = %+v / %+v", parts[0], parts[1])
	}
	if s, typ := windowsDiskEncryption(parts); s != "enabled" || typ != "software" {
		t.Errorf("disk encryption = %s/%s, want enabled/software", s, typ)
	}
}

func TestParseWindowsPartitions_Variants(t *testing.T) {
	cases := []struct {
		name                         string
		input                        string
		wantState, wantProtection    string
		wantPct                      float64 // -1: absent
		wantDiskStatus, wantDiskType string
	}{
		{"Windows Home without BitLocker", winHomeNoBitLocker, encStateUnknown, "", -1, "unknown", "unknown"},
		{"protection suspended", winSuspended, encStateFull, "off", 100, "enabled", "software"},
		{"encrypting at 42%", winEncrypting42, encStateEncrypting, "off", 42, "enabled", "software"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parts := parseWindowsPartitions(c.input)
			boot := bootPartition(parts)
			if boot == nil {
				t.Fatalf("no boot partition in %+v", parts)
			}
			if c.wantState == encStateUnknown {
				for i, p := range parts {
					if p.EncryptionState != encStateUnknown {
						t.Errorf("parts[%d].EncryptionState = %q, want unknown (never none)", i, p.EncryptionState)
					}
				}
			}
			if boot.EncryptionState != c.wantState || boot.ProtectionStatus != c.wantProtection {
				t.Errorf("C: state/protection = %q/%q, want %q/%q", boot.EncryptionState, boot.ProtectionStatus, c.wantState, c.wantProtection)
			}
			checkPercentage(t, boot.EncryptionPercentage, c.wantPct)
			if s, typ := windowsDiskEncryption(parts); s != c.wantDiskStatus || typ != c.wantDiskType {
				t.Errorf("disk encryption = %s/%s, want %s/%s", s, typ, c.wantDiskStatus, c.wantDiskType)
			}
		})
	}
}

func bootPartition(parts []shared.DiskPartition) *shared.DiskPartition {
	for i := range parts {
		if parts[i].IsBoot {
			return &parts[i]
		}
	}
	return nil
}

// checkPercentage compares got to want, where a negative want means absent.
func checkPercentage(t *testing.T, got *float64, want float64) {
	t.Helper()
	switch {
	case want < 0 && got != nil:
		t.Errorf("encryption_percentage = %v, want absent", *got)
	case want >= 0 && (got == nil || *got != want):
		t.Errorf("encryption_percentage = %v, want %v", got, want)
	}
}

func TestBitLockerEncryptionState(t *testing.T) {
	pct := func(f float64) *float64 { return &f }
	cases := []struct {
		status string
		pct    *float64
		want   string
	}{
		{"FullyEncrypted", pct(100), encStateFull},
		{"FullyDecrypted", pct(0), encStateNone},
		{"EncryptionInProgress", pct(42), encStateEncrypting},
		{"DecryptionInProgress", pct(58), encStateDecrypting},
		{"EncryptionPaused", pct(42), encStatePartial},
		{"DecryptionPaused", pct(58), encStatePartial},
		{"", pct(42), encStatePartial},
		{"", pct(0), encStateUnknown},
		{"", pct(100), encStateUnknown},
		{"", nil, encStateUnknown},
		{"SomethingNew", nil, encStateUnknown},
	}
	for _, c := range cases {
		if got := bitLockerEncryptionState(c.status, c.pct); got != c.want {
			t.Errorf("bitLockerEncryptionState(%q, %v) = %q, want %q", c.status, c.pct, got, c.want)
		}
	}
}

func TestWindowsAccessPaths(t *testing.T) {
	guid, mount := windowsAccessPaths([]any{`D:\`, `C:\mnt\data\`, `\\?\Volume{abc}\`})
	if guid != `\\?\Volume{abc}\` || mount != `C:\mnt\data\` {
		t.Errorf("got %q, %q", guid, mount)
	}
	guid, mount = windowsAccessPaths(`\\?\Volume{abc}\`)
	if guid != `\\?\Volume{abc}\` || mount != "" {
		t.Errorf("single string: got %q, %q", guid, mount)
	}
}

// TestBuildWindowsDiskDevice_MultipleDisks checks each disk carries only its
// own partitions and takes its drive letter from the first lettered one.
func TestBuildWindowsDiskDevice_MultipleDisks(t *testing.T) {
	data := parseWindowsPartitions(`{"BitLockerAvailable":true,"Partitions":[` +
		`{"PartitionNumber":1,"Type":"Basic","DriveLetter":"D","AccessPaths":["D:\\"],"Size":1000,"FileSystem":"NTFS","FreeSpace":400}]}`)
	disks := []shared.DiskDevice{
		buildWindowsDiskDevice(physicalDiskInfo{diskIndex: 0, description: "Samsung SSD 980"}, parseWindowsPartitions(winStandardInstall)),
		buildWindowsDiskDevice(physicalDiskInfo{diskIndex: 1, description: "WDC WD10EZEX"}, data),
		buildWindowsDiskDevice(physicalDiskInfo{diskIndex: -1}, windowsPartitionsForDisk(-1)),
	}
	if d := disks[0]; d.DiskNumber != 0 || len(d.Partitions) != 4 || d.DriveLetter != "C" || d.EncryptionStatus != "enabled" || d.FreeCapacity != 1571772039168 {
		t.Errorf("disk 0 = %+v", d)
	}
	if d := disks[1]; d.DiskNumber != 1 || len(d.Partitions) != 1 || d.DriveLetter != "D" || d.EncryptionStatus != "disabled" || d.EncryptionType != "none" || d.FreeCapacity != 400 {
		t.Errorf("disk 1 = %+v", d)
	}
	if d := disks[2]; d.Partitions == nil || d.EncryptionStatus != "unknown" {
		t.Errorf("disk -1 = %+v, want an empty partitions array and unknown", d)
	}
}

// TestWindowsPartitionPayload_NoSecrets guards the rule that a recovery
// password never reaches the inventory payload, even if PowerShell returned one.
func TestWindowsPartitionPayload_NoSecrets(t *testing.T) {
	const secret = "123456-123456-123456-123456-123456-123456-123456-123456"
	in := `{"BitLockerAvailable":true,"Partitions":[{"PartitionNumber":3,"DriveLetter":"C","VolumeStatus":"FullyEncrypted",` +
		`"RecoveryPassword":"` + secret + `","KeyProtectors":[{"Id":"{A}","Type":"RecoveryPassword","RecoveryPassword":"` + secret + `"}]}]}`
	d := buildWindowsDiskDevice(physicalDiskInfo{}, parseWindowsPartitions(in))
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("payload contains the recovery password: %s", out)
	}
	if !strings.Contains(string(out), `"key_protector_id":"{A}"`) {
		t.Errorf("payload lacks the protector id: %s", out)
	}
}

// TestWindowsPartitionQuery_SelectsNoSecrets keeps the PowerShell query from
// reading a key protector's RecoveryPassword or dropping partitions.
func TestWindowsPartitionQuery_SelectsNoSecrets(t *testing.T) {
	if strings.Contains(windowsPartitionQuery, "RecoveryPassword") {
		t.Error("windowsPartitionQuery reads RecoveryPassword")
	}
	if strings.Contains(windowsPartitionQuery, "-First 1") {
		t.Error("windowsPartitionQuery drops partitions with -First 1")
	}
}
