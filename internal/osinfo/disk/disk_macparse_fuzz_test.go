package disk

// Fuzz target for the diskutil plist parsers. No OS suffix: the parsers are
// pure Go and run everywhere.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzMacLayout$' -fuzztime=1m ./internal/osinfo/disk/

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func FuzzMacLayout(f *testing.F) {
	f.Add(macDiskutilList, macAPFSList(macDataFileVaultOn), "FileVault is On.")
	f.Add(macDiskutilList, macAPFSList(macDataEncrypting), "Encryption in progress: Percent completed = 1e400")
	f.Add(macDiskutilList, "", "")
	f.Add(`<plist><dict><key>AllDisksAndPartitions</key><array><dict><key>DeviceIdentifier</key><string>disk0</string>`+
		`<key>Partitions</key><array><dict><key>DeviceIdentifier</key><string>disk0s99999999999</string><key>Size</key><integer>-5</integer></dict></array></dict></array></dict></plist>`,
		`<plist><dict><key>Containers</key><array><dict><key>PhysicalStores</key><string>x</string></dict></array></dict></plist>`, "Percent completed = 101")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, list, apfs, fdesetup string) {
		l, _ := shared.PlistFromOutput(list)
		a, _ := shared.PlistFromOutput(apfs)
		for disk, parts := range parseMacLayout(l, a, fdesetup).partitions {
			if parts == nil {
				t.Fatalf("disk %q: partitions is nil, want an array", disk)
			}
			for _, p := range parts {
				checkPartitionInvariants(t, p)
			}
		}
	})
}
