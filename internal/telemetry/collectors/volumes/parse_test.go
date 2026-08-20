package volumes

import "testing"

func TestParseWindowsVolumes_Array(t *testing.T) {
	const sample = `[{"DriveLetter":"C","FileSystemLabel":"Windows","FileSystem":"NTFS","Size":511101108224,"SizeRemaining":214748364800}]`
	rows, err := parseWindowsVolumes(sample)
	if err != nil {
		t.Fatalf("parseWindowsVolumes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	v := rows[0].toVolume()
	if v.DriveLetter != "C:" || v.Label != "Windows" || v.FileSystem != "NTFS" {
		t.Errorf("volume = %+v", v)
	}
	if v.SizeBytes != 511101108224 || v.FreeBytes != 214748364800 {
		t.Errorf("sizes = %d/%d", v.SizeBytes, v.FreeBytes)
	}
}

func TestParseWindowsVolumes_SingleObject(t *testing.T) {
	const sample = `{"DriveLetter":"C","FileSystemLabel":"","FileSystem":"NTFS","Size":100,"SizeRemaining":50}`
	rows, err := parseWindowsVolumes(sample)
	if err != nil {
		t.Fatalf("parseWindowsVolumes: %v", err)
	}
	if len(rows) != 1 || rows[0].DriveLetter != "C" {
		t.Fatalf("got %+v", rows)
	}
}

func TestParseWindowsVolumes_Empty(t *testing.T) {
	rows, err := parseWindowsVolumes("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseLinuxDF(t *testing.T) {
	const sample = `Mounted on Type            1B-blocks           Avail
/          ext4     500107862016 300107862016
/boot/efi  vfat        536870912    400000000
/mnt/My Data fuse.encfs 1000000000000 500000000000
`
	got := parseLinuxDF(sample)
	if len(got) != 3 {
		t.Fatalf("got %d volumes, want 3: %+v", len(got), got)
	}
	if got[0].MountPoint != "/" || got[0].FileSystem != "ext4" || got[0].SizeBytes != 500107862016 || got[0].FreeBytes != 300107862016 {
		t.Errorf("volume 0 = %+v", got[0])
	}
	if got[1].MountPoint != "/boot/efi" || got[1].FileSystem != "vfat" {
		t.Errorf("volume 1 = %+v", got[1])
	}
	// A mount point containing a space must survive intact.
	if got[2].MountPoint != "/mnt/My Data" {
		t.Errorf("mount point with space = %q, want %q", got[2].MountPoint, "/mnt/My Data")
	}
}

func TestParseLinuxDF_Empty(t *testing.T) {
	if got := parseLinuxDF("Mounted on Type 1B-blocks Avail\n"); got != nil {
		t.Errorf("got %+v, want nil for header-only output", got)
	}
	if got := parseLinuxDF(""); got != nil {
		t.Errorf("got %+v, want nil for empty output", got)
	}
}

func TestParseDarwinDF_Classic(t *testing.T) {
	// Older-style output: Filesystem 1024-blocks Used Available Capacity Mounted-on
	const sample = `Filesystem    1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1  976490568 12057648 476420864     3%    /
/dev/disk3s6    976490568   331488 476420864     1%    /System/Volumes/VM
`
	got := parseDarwinDF(sample)
	if len(got) != 2 {
		t.Fatalf("got %d volumes, want 2: %+v", len(got), got)
	}
	if got[0].MountPoint != "/" {
		t.Errorf("mount point = %q, want /", got[0].MountPoint)
	}
	if got[0].SizeBytes != 976490568*1024 {
		t.Errorf("size = %d, want %d", got[0].SizeBytes, 976490568*1024)
	}
	if got[0].FreeBytes != 476420864*1024 {
		t.Errorf("free = %d, want %d", got[0].FreeBytes, 476420864*1024)
	}
	if got[1].MountPoint != "/System/Volumes/VM" {
		t.Errorf("mount point = %q", got[1].MountPoint)
	}
}

func TestParseDarwinDF_WithIusedColumns(t *testing.T) {
	// Newer-style output with iused/ifree/%iused inserted before Mounted-on.
	const sample = `Filesystem    1024-blocks      Used Available Capacity iused    ifree %iused  Mounted on
/dev/disk3s1s1  976490568 12057648 476420864     3%  312000 4864000    6%   /
`
	got := parseDarwinDF(sample)
	if len(got) != 1 {
		t.Fatalf("got %d volumes, want 1: %+v", len(got), got)
	}
	if got[0].MountPoint != "/" {
		t.Errorf("mount point = %q, want / (iused/ifree/%%iused columns must not leak into it)", got[0].MountPoint)
	}
	if got[0].SizeBytes != 976490568*1024 {
		t.Errorf("size = %d, want %d", got[0].SizeBytes, 976490568*1024)
	}
}

func TestParseDarwinDF_Empty(t *testing.T) {
	if got := parseDarwinDF("Filesystem 1024-blocks Used Available Capacity Mounted on\n"); got != nil {
		t.Errorf("got %+v, want nil for header-only output", got)
	}
}
