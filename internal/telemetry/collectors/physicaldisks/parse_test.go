package physicaldisks

import "testing"

func TestNormalizeMediaType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"SSD", "ssd"}, {"HDD", "hdd"}, {"Solid State Drive", "ssd"},
		{"Unspecified", "unspecified"}, {"", "unspecified"}, {"Weird", "unspecified"},
	}
	for _, tc := range tests {
		if got := normalizeMediaType(tc.in); got != tc.want {
			t.Errorf("normalizeMediaType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeBusType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"NVMe", "nvme"}, {"SATA", "sata"}, {"USB", "usb"}, {"SAS", "sas"},
		{"RAID", "raid"}, {"", ""}, {"Weird", "weird"},
	}
	for _, tc := range tests {
		if got := normalizeBusType(tc.in); got != tc.want {
			t.Errorf("normalizeBusType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseWindowsDisks_Array(t *testing.T) {
	const sample = `[{"Id":"0","Model":"Samsung SSD 980","Serial":"S1","Size":500107862016,"MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Temperature":35,"PowerOnHours":1200,"Wear":2}]`
	rows, err := parseWindowsDisks(sample)
	if err != nil {
		t.Fatalf("parseWindowsDisks: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	d := rows[0].toDisk()
	if d.ID != "0" || d.Model != "Samsung SSD 980" || d.SizeBytes != 500107862016 {
		t.Errorf("disk = %+v", d)
	}
	if d.MediaType != "ssd" || d.BusType != "nvme" {
		t.Errorf("media/bus = %q/%q", d.MediaType, d.BusType)
	}
	if d.SMART == nil {
		t.Fatal("expected SMART data")
	}
	if d.SMART.TemperatureCelsius == nil || *d.SMART.TemperatureCelsius != 35 {
		t.Errorf("temperature = %v", d.SMART.TemperatureCelsius)
	}
}

func TestParseWindowsDisks_SingleObject(t *testing.T) {
	// A single disk serializes as a bare object, not a one-element array.
	const sample = `{"Id":"0","Model":"WDC WD10","Serial":"S2","Size":1000204886016,"MediaType":"HDD","BusType":"SATA","Health":"Healthy"}`
	rows, err := parseWindowsDisks(sample)
	if err != nil {
		t.Fatalf("parseWindowsDisks: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "0" {
		t.Fatalf("got %+v", rows)
	}
}

func TestParseWindowsDisks_Empty(t *testing.T) {
	rows, err := parseWindowsDisks("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseLsblkDisks(t *testing.T) {
	const sample = `{"blockdevices":[
		{"name":"sda","type":"disk","model":"Samsung SSD","serial":"S1","size":500107862016,"rota":"0","tran":"sata"},
		{"name":"sda1","type":"part","model":"","serial":"","size":1048576,"rota":"0","tran":null},
		{"name":"sdb","type":"disk","model":"ST1000","serial":"S2","size":"1000204886016","rota":"1","tran":"sata"}
	]}`
	disks, err := parseLsblkDisks(sample)
	if err != nil {
		t.Fatalf("parseLsblkDisks: %v", err)
	}
	if len(disks) != 2 {
		t.Fatalf("got %d disks, want 2 (partition should be excluded): %+v", len(disks), disks)
	}

	d0 := disks[0].toDisk()
	if d0.ID != "sda" || d0.MediaType != "ssd" || d0.SizeBytes != 500107862016 {
		t.Errorf("disk 0 = %+v", d0)
	}

	// String-typed size/rota (older util-linux) must parse the same as
	// numeric.
	d1 := disks[1].toDisk()
	if d1.ID != "sdb" || d1.MediaType != "hdd" || d1.SizeBytes != 1000204886016 {
		t.Errorf("disk 1 (string-encoded fields) = %+v", d1)
	}
}

func TestSmartFromSmartctl_NVMe(t *testing.T) {
	const sample = `{"smart_status":{"passed":true},"temperature":{"current":42},"power_on_time":{"hours":500},"nvme_percentage_used":7}`
	r, err := parseSmartctlJSON(sample)
	if err != nil {
		t.Fatalf("parseSmartctlJSON: %v", err)
	}
	s := smartFromSmartctl(r)
	if s == nil {
		t.Fatal("expected SMART summary")
	}
	if s.Healthy == nil || !*s.Healthy {
		t.Errorf("healthy = %v, want true", s.Healthy)
	}
	if s.TemperatureCelsius == nil || *s.TemperatureCelsius != 42 {
		t.Errorf("temperature = %v", s.TemperatureCelsius)
	}
	if s.PowerOnHours == nil || *s.PowerOnHours != 500 {
		t.Errorf("power on hours = %v", s.PowerOnHours)
	}
	if s.WearPercentage == nil || *s.WearPercentage != 7 {
		t.Errorf("wear = %v, want 7 (direct NVMe indicator)", s.WearPercentage)
	}
}

func TestSmartFromSmartctl_ATAWearAttribute(t *testing.T) {
	const sample = `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[
		{"id":5,"value":100},
		{"id":177,"value":92}
	]}}`
	r, err := parseSmartctlJSON(sample)
	if err != nil {
		t.Fatalf("parseSmartctlJSON: %v", err)
	}
	s := smartFromSmartctl(r)
	if s == nil || s.WearPercentage == nil {
		t.Fatal("expected wear percentage from ATA attribute 177")
	}
	if *s.WearPercentage != 8 {
		t.Errorf("wear = %v, want 8 (100 - value=92)", *s.WearPercentage)
	}
}

func TestSmartFromSmartctl_NoData(t *testing.T) {
	if got := smartFromSmartctl(&smartctlResult{}); got != nil {
		t.Errorf("got %+v, want nil for a result with no usable fields", got)
	}
	if got := smartFromSmartctl(nil); got != nil {
		t.Errorf("got %+v, want nil for a nil result", got)
	}
}

func TestParseDiskutilListPhysical(t *testing.T) {
	const sample = `/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.3 GB   disk0
   1:                        EFI EFI                     314.6 MB   disk0s1
   2:                 Apple_APFS Container disk1         499.8 GB   disk0s2

/dev/disk1 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      APFS Container Scheme -                      +499.8 GB   disk1
                                 Physical Store disk0s2

/dev/disk2 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:     FDisk_partition_scheme                        *32.0 GB    disk2
`
	got := parseDiskutilListPhysical(sample)
	want := []string{"disk0", "disk2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseDiskutilInfo(t *testing.T) {
	const sample = `   Device Identifier:        disk0
   Device / Media Name:      APPLE SSD AP0512Q
   Disk Size:                 500.3 GB (500277790720 Bytes) (exactly 977105264 512-Byte-Units)
   Solid State:               Yes
   SMART Status:              Verified
`
	info := parseDiskutilInfo(sample)
	if info["device / media name"] != "APPLE SSD AP0512Q" {
		t.Errorf("model = %q", info["device / media name"])
	}
	if info["solid state"] != "Yes" {
		t.Errorf("solid state = %q", info["solid state"])
	}
	if info["smart status"] != "Verified" {
		t.Errorf("smart status = %q", info["smart status"])
	}
}

func TestParseDarwinDiskSizeBytes(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"500.3 GB (500277790720 Bytes) (exactly 977105264 512-Byte-Units)", 500277790720},
		{"", 0},
		{"no parens here", 0},
	}
	for _, tc := range tests {
		if got := parseDarwinDiskSizeBytes(tc.in); got != tc.want {
			t.Errorf("parseDarwinDiskSizeBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
