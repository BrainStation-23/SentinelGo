//go:build windows

package disk

// Fuzz target for the Get-PhysicalDisk / Get-BitLockerVolume JSON parsers.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Windows).
// To fuzz: go test -run='^$' -fuzz='^FuzzWindowsDiskJSON$' -fuzztime=1m ./internal/osinfo/disk/

import (
	"encoding/json"
	"testing"
)

func FuzzWindowsDiskJSON(f *testing.F) {
	for _, s := range []string{
		`{"DeviceId":0,"FriendlyName":"Samsung SSD 980","SerialNumber":"S1","MediaType":"SSD","BusType":"NVMe","HealthStatus":"Healthy","Size":512110190592}`,
		`[{"DeviceId":1,"Size":2000398934016},{"DeviceId":0,"Size":256060514304}]`,
		`{"DriveLetter":"C","FreeSpace":123456789,"FileSystem":"NTFS","ProtectionStatus":1,"EncryptionMethod":"XtsAes256"}`,
		`{"DeviceId":-1,"Size":-1}`, `{"DeviceId":1e300,"Size":1e300}`, `{"FreeSpace":-5,"ProtectionStatus":1e300}`,
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
		var result map[string]any
		if json.Unmarshal([]byte(s), &result) == nil {
			_ = parseBitLockerResult(result)
		}
	})
}

// TestParsePhysicalDiskItem_RejectsBadNumbers guards against negative or
// out-of-range JSON numbers turning into a bogus disk index or a huge size.
func TestParsePhysicalDiskItem_RejectsBadNumbers(t *testing.T) {
	info := parsePhysicalDiskItem(map[string]any{"DeviceId": -3.0, "Size": -1.0})
	if info.diskIndex != -1 || info.totalBytes != 0 {
		t.Errorf("got diskIndex=%d totalBytes=%d, want -1 and 0", info.diskIndex, info.totalBytes)
	}
	vol := parseBitLockerResult(map[string]any{"FreeSpace": -5.0, "ProtectionStatus": 1e300})
	if vol.freeBytes != 0 || vol.encryptionStatus != "unknown" {
		t.Errorf("got freeBytes=%d status=%q, want 0 and unknown", vol.freeBytes, vol.encryptionStatus)
	}
}
