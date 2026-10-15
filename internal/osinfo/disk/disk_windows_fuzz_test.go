//go:build windows

package disk

// Fuzz targets for the Get-PhysicalDisk and partition/BitLocker JSON parsers.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Windows).
// To fuzz: go test -run='^$' -fuzz='^FuzzWindowsDiskJSON$' -fuzztime=1m ./internal/osinfo/disk/
//          go test -run='^$' -fuzz='^FuzzWindowsPartitionsJSON$' -fuzztime=1m ./internal/osinfo/disk/

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func FuzzWindowsDiskJSON(f *testing.F) {
	for _, s := range []string{
		`{"DeviceId":0,"FriendlyName":"Samsung SSD 980","SerialNumber":"S1","MediaType":"SSD","BusType":"NVMe","HealthStatus":"Healthy","Size":512110190592}`,
		`[{"DeviceId":1,"Size":2000398934016},{"DeviceId":0,"Size":256060514304}]`,
		`{"DeviceId":-1,"Size":-1}`, `{"DeviceId":1e300,"Size":1e300}`,
		`[null]`, `null`, `[]`, `{`, ``,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		for _, item := range parsePhysicalDisksJSON(s) {
			info := parsePhysicalDiskItem(item)
			if info.diskIndex < -1 {
				t.Fatalf("diskIndex = %d, want -1 or a valid index", info.diskIndex)
			}
		}
	})
}

func FuzzWindowsPartitionsJSON(f *testing.F) {
	for _, s := range []string{
		winStandardInstall, winHomeNoBitLocker, winSuspended, winEncrypting42,
		`{"BitLockerAvailable":true,"Partitions":{"PartitionNumber":1,"Type":"Basic","VolumeStatus":"FullyEncrypted"}}`,
		`{"Partitions":[{"PartitionNumber":-1,"Size":-1,"FreeSpace":1e300,"EncryptionPercentage":1e300,"VolumeStatus":"X"}]}`,
		`{"Partitions":[null,1,"x",{"KeyProtectors":{"Id":"{a}","Type":"RecoveryPassword"},"VolumeStatus":"FullyEncrypted"}]}`,
		`{"Partitions":[{"DriveLetter":"\u0000","AccessPaths":"C:\\"}]}`,
		`null`, `[]`, `{`, ``,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		parts := parseWindowsPartitions(s)
		if parts == nil {
			t.Fatal("parseWindowsPartitions returned nil, want a non-nil slice")
		}
		for _, p := range parts {
			checkWindowsPartition(t, p)
		}
		_, _ = windowsDiskEncryption(parts)
	})
}

// checkWindowsPartition fails t if p breaks an invariant the server relies on.
func checkWindowsPartition(t *testing.T, p shared.DiskPartition) {
	t.Helper()
	checkPartitionInvariants(t, p)
	if p.DriveLetter != "" && (len(p.DriveLetter) != 1 || p.DriveLetter[0] < 'A' || p.DriveLetter[0] > 'Z') {
		t.Fatalf("drive_letter = %q, want one bare letter", p.DriveLetter)
	}
}

// TestParsePhysicalDiskItem_RejectsBadNumbers guards against negative or
// out-of-range JSON numbers turning into a bogus disk index or a huge size.
func TestParsePhysicalDiskItem_RejectsBadNumbers(t *testing.T) {
	info := parsePhysicalDiskItem(map[string]any{"DeviceId": -3.0, "Size": -1.0})
	if info.diskIndex != -1 || info.totalBytes != 0 {
		t.Errorf("got diskIndex=%d totalBytes=%d, want -1 and 0", info.diskIndex, info.totalBytes)
	}
	parts := parseWindowsPartitions(`{"Partitions":[{"PartitionNumber":-2,"Size":-1,"FreeSpace":1e300}]}`)
	if len(parts) != 1 || parts[0].PartitionNumber != 0 || parts[0].SizeBytes != 0 || parts[0].FreeBytes != 0 {
		t.Errorf("got %+v, want zeroed numbers", parts)
	}
}
