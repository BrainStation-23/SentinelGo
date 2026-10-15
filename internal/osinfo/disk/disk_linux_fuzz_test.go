//go:build linux

package disk

// Fuzz target for the lsblk partition-tree parser.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Linux).
// To fuzz: go test -run='^$' -fuzz='^FuzzLinuxDiskLayouts$' -fuzztime=1m ./internal/osinfo/disk/

import "testing"

func FuzzLinuxDiskLayouts(f *testing.F) {
	for _, s := range []string{
		lsblkLUKSInstall, lsblkBasicColumns, lsblkWholeDiskLUKS,
		`{"blockdevices":[{"name":"sda","type":"disk","children":[{"name":"sda1","type":"part","size":-1,"partn":1e300}]}]}`,
		`{"blockdevices":[{"name":"sda","type":"disk","children":[{"name":"sda1","type":"part","size":"x","partn":"-3","mountpoint":"[SWAP]"}]}]}`,
		`{"blockdevices":[{"name":"d","type":"disk","children":[{"type":"part","children":[{"type":"crypt","children":[{"mountpoint":"/"}]}]}]}]}`,
		`null`, `{}`, `{`, ``,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		for name, l := range parseLinuxDiskLayouts(s) {
			if l.partitions == nil {
				t.Fatalf("disk %q: partitions is nil, want an array", name)
			}
			for _, p := range l.partitions {
				checkPartitionInvariants(t, p)
			}
			_, _ = summarizeDiskEncryption(l.partitions)
		}
	})
}
